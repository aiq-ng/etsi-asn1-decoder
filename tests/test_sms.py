import json
import random
import unittest

from etsi_asn1_decoder.sms import decode_tpdu, decode_gsm7, decode_dcs, reassemble_sms


# Fixed wire vectors: international address +12345, 2026-09-24 12:34:56 +01:00.
ADDRESS = bytes.fromhex("05912143f5")
STAMP = bytes.fromhex("62904221436540")
HELLO = bytes.fromhex("e8329bfd06")  # GSM septets for 'hello'


def pack(codes, header=b""):
    """Test encoder uses individual bits, independent of decoder's integer shifts."""
    bits = [(b >> i) & 1 for b in header for i in range(8)]
    while len(bits) % 7:
        bits.append(0)
    count = len(bits) // 7 + len(codes)
    bits.extend((c >> i) & 1 for c in codes for i in range(7))
    while len(bits) % 8:
        bits.append(0)
    return count, bytes(sum(bits[j + i] << i for i in range(8)) for j in range(0, len(bits), 8))


def deliver(payload=HELLO, udl=5, dcs=0, first=0, address=ADDRESS, stamp=STAMP):
    return bytes([first]) + address + bytes([0, dcs]) + stamp + bytes([udl]) + payload


def submit(payload=HELLO, udl=5, dcs=0, vpf=0, validity=b"", first=1):
    return bytes([first | vpf << 3, 42]) + ADDRESS + bytes([0, dcs]) + validity + bytes([udl]) + payload


def segment(sequence, text, *, total=2, reference=7, wide=False, dcs=0, ports=b""):
    concat = (bytes([8, 4]) + reference.to_bytes(2, "big") if wide
              else bytes([0, 3, reference])) + bytes([total, sequence])
    body = concat + ports
    header = bytes([len(body)]) + body
    if dcs == 0:
        udl, payload = pack(text, header)
    else:
        payload = header + text
        udl = len(payload)
    return decode_tpdu(deliver(payload, udl, dcs, 0x40), direction="sc-to-ms")


class SMSDecodingTests(unittest.TestCase):
    def test_fixed_deliver_vector_and_metadata(self):
        wire = bytes.fromhex("0005912143f500006290422143654005e8329bfd06")
        decoded = decode_tpdu(wire)
        self.assertEqual(decoded["type"], "SMS-DELIVER")
        self.assertEqual(decoded["message"], "hello")
        self.assertEqual(decoded["originating_address"], "+12345")
        self.assertEqual(decoded["protocol_id"], 0)
        self.assertEqual(decoded["timestamp"], {
            "year_two_digits": 26, "month": 9, "day": 24, "hour": 12,
            "minute": 34, "second": 56, "timezone_offset_minutes": 60,
            "raw_hex": STAMP.hex(),
        })
        self.assertEqual(decoded["raw_hex"], wire.hex())
        json.dumps(decoded)

    def test_submit_all_validity_formats(self):
        for form, validity, expected in (
            (0, b"", None), (2, b"\xaa", 4 * 86400), (3, STAMP, None),
            (1, bytes.fromhex("42050000000000"), 5),
        ):
            with self.subTest(form=form):
                result = decode_tpdu(submit(vpf=form, validity=validity))
                self.assertEqual(result["type"], "SMS-SUBMIT")
                self.assertEqual(result["message"], "hello")
                self.assertEqual(result["destination_address"], "+12345")
                self.assertEqual(result["message_reference"], 42)
                if expected:
                    self.assertEqual(result["validity_period"]["seconds"], expected)
                if form == 3:
                    self.assertEqual(result["validity_period"]["day"], 24)

    def test_relative_validity_boundaries(self):
        for wire, seconds in [(0, 300), (143, 43200), (144, 45000),
                              (167, 86400), (168, 172800), (196, 2592000),
                              (197, 3024000), (255, 38102400)]:
            with self.subTest(wire=wire):
                result = decode_tpdu(submit(vpf=2, validity=bytes([wire])), "ms-to-sc")
                self.assertEqual(result["validity_period"]["seconds"], seconds)

    def test_status_report_with_optional_data(self):
        base = b"\x02\x2a" + ADDRESS + STAMP + STAMP + b"\x00"
        result = decode_tpdu(base)
        self.assertEqual(result["type"], "SMS-STATUS-REPORT")
        self.assertEqual(result["status"], 0)
        self.assertEqual(result["recipient_address"], "+12345")
        self.assertEqual(result["discharge_time"]["hour"], 12)
        self.assertNotIn("message", result)
        result = decode_tpdu(base + b"\x07\x41\x00\x05" + HELLO, "sc-to-ms")
        self.assertEqual(result["protocol_id"], 0x41)
        self.assertEqual(result["message"], "hello")

    def test_deliver_and_submit_report_ack_and_error(self):
        for mti, direction, kind, timestamp in (
            (0, "ms-to-sc", "SMS-DELIVER-REPORT", b""),
            (1, "sc-to-ms", "SMS-SUBMIT-REPORT", STAMP),
        ):
            for report_kind, failure in (("ack", b""), ("error", b"\xd3")):
                with self.subTest(kind=kind, report_kind=report_kind):
                    wire = bytes([mti]) + failure + b"\x07" + timestamp + b"\x00\x08\x04\x00H\x00i"
                    result = decode_tpdu(wire, direction, report_kind)
                    self.assertEqual(result["type"], kind)
                    self.assertEqual(result["message"], "Hi")
                    self.assertEqual(result["report_kind"], report_kind)
                    if failure:
                        self.assertEqual(result["failure_cause"], 0xD3)

    def test_minimal_reports_and_default_dcs(self):
        self.assertEqual(decode_tpdu(b"\x00\x00", "ms-to-sc", "ack")["type"], "SMS-DELIVER-REPORT")
        result = decode_tpdu(b"\x00\x04\x05" + HELLO, "ms-to-sc", "ack")
        self.assertEqual(result["message"], "hello")
        self.assertTrue(result["dcs_defaulted"])
        self.assertIsNone(decode_tpdu(b"\x00\x7f\x00", "ms-to-sc", "error"))

    def test_parameter_extension(self):
        result = decode_tpdu(b"\x00\x84\x00\x05" + HELLO, "ms-to-sc", "ack")
        self.assertEqual(result["parameter_indicators"], [0x84, 0])
        self.assertEqual(result["message"], "hello")
        result = decode_tpdu(b"\x00\x08\xff\xfe", "ms-to-sc", "ack")
        self.assertEqual(result["parameter_extension_hex"], "fffe")
        self.assertIsNone(decode_tpdu(b"\x00\x80", "ms-to-sc", "ack"))

    def test_command_binary_and_header(self):
        wire = b"\x02\x2a\x00\x02\x03" + ADDRESS + b"\x03ABC"
        result = decode_tpdu(wire)
        self.assertEqual(result["type"], "SMS-COMMAND")
        self.assertEqual(result["command_type"], 2)
        self.assertEqual(result["message_number"], 3)
        self.assertEqual(result["command_data_hex"], "414243")
        self.assertNotIn("message", result)
        header = bytes.fromhex("040402f001")
        wire = b"\x42\x2a\x00\x02\x03" + ADDRESS + bytes([len(header) + 1]) + header + b"Z"
        result = decode_tpdu(wire, "ms-to-sc")
        self.assertEqual(result["user_data_header"]["ports"]["destination"], 240)
        self.assertEqual(result["command_data_hex"], "5a")

    def test_direction_and_report_hints_are_enforced(self):
        self.assertIsNone(decode_tpdu(deliver(), "ms-to-sc", "error"))
        self.assertIsNone(decode_tpdu(submit(), "ms-to-sc", "ack"))
        for kw in ({"direction": "outgoing"}, {"report_kind": "success"}):
            with self.assertRaises(ValueError):
                decode_tpdu(deliver(), **kw)

    def test_ambiguous_reports_do_not_guess(self):
        # ACK: extended PI 0x80,0. ERROR: FCS 0x80, PI 0.
        result = decode_tpdu(bytes.fromhex("008000"), "ms-to-sc")
        self.assertEqual(result["type"], "SMS-AMBIGUOUS")
        self.assertNotIn("message", result)
        self.assertEqual(len(result["candidates"]), 2)
        for kind in ("ack", "error"):
            self.assertEqual(decode_tpdu(bytes.fromhex("008000"), "ms-to-sc", kind)["report_kind"], kind)

    def test_alphanumeric_originator(self):
        _, value = pack(b"BANK")
        address = bytes([7, 0xD0]) + value
        self.assertEqual(decode_tpdu(deliver(address=address), "sc-to-ms")["originating_address"], "BANK")

    def test_national_number_special_digits_and_filler(self):
        address = bytes.fromhex("0581badcfe")
        self.assertEqual(decode_tpdu(deliver(address=address), "sc-to-ms")["originating_address"], "*#abc")
        for address in (bytes.fromhex("0591214305"), bytes.fromhex("0591214ff5"), bytes.fromhex("05012143f5")):
            self.assertIsNone(decode_tpdu(deliver(address=address), "sc-to-ms"))

    def test_gsm_basic_and_extension_characters(self):
        # Fixed extension wire bytes: ESC,0x65 = euro.
        self.assertEqual(decode_gsm7(bytes.fromhex("9b32"), 2), "€")
        codes = [0, 1, 2, 16, 27, 10, 27, 20, 27, 40, 27, 41, 27, 47,
                 27, 60, 27, 61, 27, 62, 27, 64, 27, 101]
        udl, payload = pack(codes)
        result = decode_tpdu(deliver(payload, udl), "sc-to-ms")
        self.assertEqual(result["message"], "@£$Δ\f^{}\\[~]|€")
        self.assertEqual(decode_gsm7(b"", 0), "")

    def test_ucs2_and_binary(self):
        payload = "你好".encode("utf-16-be")
        self.assertEqual(decode_tpdu(deliver(payload, len(payload), 8))["message"], "你好")
        result = decode_tpdu(deliver(b"hello", 5, 4))
        self.assertEqual(result["encoding"], "8-bit")
        self.assertEqual(result["user_data_hex"], b"hello".hex())
        self.assertNotIn("message", result)
        self.assertNotIn("decoded_text_preview", result)

    def test_dcs_groups(self):
        for value in (0x00, 0x10, 0x40, 0x50, 0xC8, 0xD8, 0xF0, 0xF3, 0x80, 0xFC):
            with self.subTest(value=value):
                result = decode_tpdu(deliver(dcs=value), "sc-to-ms")
                self.assertEqual(result["message"], "hello")
        for value in (0x08, 0x48, 0xE0, 0xE8):
            with self.subTest(value=value):
                result = decode_tpdu(deliver(b"\x00A", 2, value), "sc-to-ms")
                self.assertEqual(result["message"], "A")
        for value in (0x04, 0x44, 0xF4, 0xF7):
            self.assertNotIn("message", decode_tpdu(deliver(b"ABC", 3, value), "sc-to-ms"))
        self.assertEqual(decode_dcs(0xF3)["message_class"], 3)
        self.assertEqual(decode_dcs(0xD9)["message_waiting"], {"active": True, "discard": False, "kind": "fax"})
        self.assertEqual(decode_dcs(0x40)["group"], "automatic-deletion")
        self.assertTrue(decode_dcs(0x80)["reserved"])

    def test_compressed_payload_is_not_misdecoded(self):
        result = decode_tpdu(deliver(b"ABC", 3, 0x20), "sc-to-ms")
        self.assertTrue(result["coding_scheme"]["compressed"])
        self.assertEqual(result["user_data_hex"], "414243")
        self.assertNotIn("message", result)
        self.assertIn("Compressed", result["text_decoding_error"])

    def test_udhi_alignment_for_every_padding_width(self):
        for length in range(8):
            # Unknown IE is preserved; vary its length to exercise all fill bits.
            body = bytes([0x70, length]) + bytes(length)
            header = bytes([len(body)]) + body
            udl, payload = pack([65, 27, 101, 66], header)
            result = decode_tpdu(deliver(payload, udl, first=0x40), "sc-to-ms")
            self.assertEqual(result["message"], "A€B", length)
            self.assertEqual(result["user_data_header"]["elements"][0]["id"], 0x70)

    def test_header_only_and_zero_length_text(self):
        self.assertEqual(decode_tpdu(deliver(b"", 0), "sc-to-ms")["message"], "")
        udl, payload = pack([], bytes.fromhex("050003010101"))
        self.assertEqual(decode_tpdu(deliver(payload, udl, first=0x40), "sc-to-ms")["message"], "")

    def test_header_fields(self):
        result = segment(2, b"ok", wide=True, reference=0x1234, ports=bytes.fromhex("05040b8423f0"))
        header = result["user_data_header"]
        self.assertEqual(header["concatenation"], {"reference": 0x1234, "reference_bits": 16, "total": 2, "sequence": 2})
        self.assertEqual(header["ports"], {"destination": 2948, "source": 9200, "bits": 16})
        body = bytes.fromhex("24010125010101028003")
        udl, payload = pack(b"A", bytes([len(body)]) + body)
        result = decode_tpdu(deliver(payload, udl, first=0x40), "sc-to-ms")
        self.assertEqual(result["user_data_header"]["single_shift"], 1)
        self.assertEqual(result["user_data_header"]["locking_shift"], 1)
        self.assertEqual(result["user_data_header"]["message_waiting"][0]["count"], 3)
        self.assertIn("text_decoding_error", result)
        self.assertNotIn("message", result)

    def test_malformed_headers_do_not_produce_messages(self):
        for header in (b"", b"\x05\x00", bytes.fromhex("0100"), bytes.fromhex("0400020101"),
                       bytes.fromhex("050003010200"), bytes.fromhex("050003010203")):
            with self.subTest(header=header.hex()):
                self.assertIsNone(decode_tpdu(deliver(header, len(header), 4, 0x40), "sc-to-ms"))

    def test_duplicate_and_mutually_exclusive_headers_use_last(self):
        header = bytes.fromhex("100402f00105040b8423f0240100240101")
        result = decode_tpdu(deliver(header, len(header), 4, 0x40), "sc-to-ms")
        self.assertEqual(result["user_data_header"]["ports"]["bits"], 16)
        self.assertEqual(result["user_data_header"]["single_shift"], 1)
        self.assertEqual(len(result["user_data_header"]["elements"]), 4)

    def test_invalid_text_is_preserved_without_partial_message(self):
        for payload, udl, dcs in ((b"\x00", 1, 8), (b"\xd8\x00", 2, 8),
                                  (b"\x1b", 1, 0), (b"\x9b\x00", 2, 0)):
            result = decode_tpdu(deliver(payload, udl, dcs), "sc-to-ms")
            self.assertIn("text_decoding_error", result)
            self.assertNotIn("message", result)
            self.assertEqual(result["user_data_hex"], payload.hex())

    def test_truncation_and_trailing_data(self):
        for wire, direction in ((deliver(), "sc-to-ms"), (submit(), "ms-to-sc")):
            for end in range(len(wire)):
                with self.subTest(end=end, direction=direction):
                    self.assertIsNone(decode_tpdu(wire[:end], direction))
            self.assertIsNone(decode_tpdu(wire + b"\x00", direction))
        with self.assertRaises(ValueError):
            decode_gsm7(b"\x00", 2)
        with self.assertRaises(ValueError):
            decode_gsm7(b"\x00", 1, 1)
        self.assertIsNone(decode_tpdu(deliver(bytes(141), 141, 4), "sc-to-ms"))
        self.assertIsNone(decode_tpdu(deliver(first=3)))

    def test_timestamp_sign_and_validation(self):
        result = decode_tpdu(deliver(stamp=STAMP[:-1] + b"\x8a"), "sc-to-ms")
        self.assertEqual(result["timestamp"]["timezone_offset_minutes"], -420)
        for stamp in (bytes.fromhex("62f04221436540"), bytes.fromhex("62313221436540"), bytes(7)):
            self.assertIsNone(decode_tpdu(deliver(stamp=stamp), "sc-to-ms"))

    def test_random_input_is_bounded_and_json_safe(self):
        rng = random.Random(4023)
        for _ in range(2000):
            data = rng.randbytes(rng.randrange(180))
            result = decode_tpdu(data)
            json.dumps(result)
            if result:
                self.assertEqual(result["raw_hex"], data.hex())


class SMSReassemblyTests(unittest.TestCase):
    def test_out_of_order_and_identical_duplicates(self):
        first, second = segment(1, b"hello "), segment(2, b"world")
        result = reassemble_sms([second, first, first])
        self.assertTrue(result["complete"])
        self.assertEqual(result["message"], "hello world")
        self.assertEqual(result["received"], 2)
        self.assertEqual(result["segments_raw_hex"], [first["raw_hex"], second["raw_hex"]])

    def test_missing_parts_are_explicit(self):
        result = reassemble_sms([segment(2, b"world", total=3)])
        self.assertFalse(result["complete"])
        self.assertEqual(result["missing_segments"], [1, 3])
        self.assertNotIn("message", result)

    def test_malformed_text_segments_are_not_silently_repaired(self):
        # Each UCS-2 segment has an incomplete code unit. Joining bytes would
        # hide the corruption and incorrectly manufacture 'A'.
        result = reassemble_sms([segment(1, b"\x00", dcs=8), segment(2, b"A", dcs=8)])
        self.assertTrue(result["complete"])
        self.assertNotIn("message", result)
        self.assertIn("text_decoding_error", result)

    def test_binary_and_ucs2_reassembly(self):
        for dcs, chunks, expected in ((4, [b"ABC", b"\x00\xff"], None),
                                     (8, ["你".encode("utf-16-be"), "好".encode("utf-16-be")], "你好")):
            result = reassemble_sms([segment(i + 1, p, dcs=dcs, wide=True) for i, p in enumerate(chunks)])
            self.assertEqual(result["user_data_hex"], b"".join(chunks).hex())
            self.assertEqual(result.get("message"), expected)

    def test_conflicts_and_mixed_messages_rejected(self):
        first = segment(1, b"hello ")
        for other in (segment(1, b"changed"), segment(2, b"world", reference=9),
                      segment(2, b"world", total=3), segment(2, b"world", wide=True),
                      segment(2, b"world", dcs=4), segment(2, b"world", ports=bytes.fromhex("0402f001"))):
            with self.assertRaises(ValueError):
                reassemble_sms([first, other])
        other = segment(2, b"world")
        other["originating_address"] = "+98765"
        with self.assertRaises(ValueError):
            reassemble_sms([first, other])
        for parts in ([], [decode_tpdu(deliver())]):
            with self.assertRaises(ValueError):
                reassemble_sms(parts)


if __name__ == "__main__":
    unittest.main()
