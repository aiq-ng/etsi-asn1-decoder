import unittest
from unittest.mock import patch

import asn1tools

from etsi_asn1_decoder.decoder import ASN1Decoder


class FieldFormatTests(unittest.TestCase):
    def setUp(self):
        self.decoder = ASN1Decoder.__new__(ASN1Decoder)
        self.decoder.field_formats = {}

    def test_no_length_or_name_guesses(self):
        for field in ("", "imsi", "imei", "msisdn", "callingPartyNumber", "address",
                      "identifier", "liid", "cell", "plmn", "timestamp", "uuid"):
            for data in (bytes.fromhex("2143f5"), bytes.fromhex("19325476981032f4"),
                         b"12345678", bytes(range(16))):
                with self.subTest(field=field, data=data.hex()):
                    self.assertEqual(self.decoder.smart_decode_hex(data, field), "hex:" + data.hex())
                    self.assertEqual(self.decoder.make_json_safe(data, context_path=field), "hex:" + data.hex())

    def test_exact_paths_do_not_match_ancestors_or_similar_names(self):
        self.decoder.field_formats = {"target.imsi": "imsi-tbcd"}
        data = bytes.fromhex("19325476981032f4")
        self.assertEqual(self.decoder.smart_decode_hex(data, "target.imsi"), "912345678901234")
        for path in ("other.imsi", "target.imsi.extra", "target.imsiHash", "target.IMSI"):
            self.assertEqual(self.decoder.smart_decode_hex(data, path), "hex:" + data.hex())

    def test_same_bytes_require_the_selected_format(self):
        self.decoder.field_formats = {"rawNumber": "tbcd-digits", "mapNumber": "map-address"}
        data = bytes.fromhex("912143f5")
        self.assertEqual(self.decoder.smart_decode_hex(data, "rawNumber"), "1912345")
        result = self.decoder.smart_decode_hex(data, "mapNumber")
        self.assertEqual(result["number"], "12345")
        self.assertEqual(result["nature_of_address"], 1)
        self.assertEqual(result["numbering_plan"], 1)

    def test_imsi_preserves_leading_digits(self):
        for data, expected in (("11325476981032f4", "112345678901234"),
                               ("19325476981032f4", "912345678901234"),
                               ("00325476981032f4", "002345678901234")):
            self.assertEqual(self.decoder.decode_imsi(bytes.fromhex(data)), expected)

    def test_invalid_tbcd_cannot_fall_through(self):
        self.decoder.field_formats = {"identity": "imsi-tbcd"}
        for raw in ("1f2345", "f12345", "21f345", "2143ff", "1234567890123456", "12"):
            data = bytes.fromhex(raw)
            self.assertEqual(self.decoder.smart_decode_hex(data, "identity"), "hex:" + raw)
        self.assertIsNone(self.decoder.decode_map_format_number(bytes.fromhex("112143f5")))

    def test_isup_has_two_header_octets_and_zero_filler(self):
        self.decoder.field_formats = {"called": "isup-called", "calling": "isup-calling"}
        called = self.decoder.smart_decode_hex(bytes.fromhex("8410214305"), "called")
        self.assertEqual(called["number"], "12345")
        self.assertEqual(called["nature_of_address"], 4)
        calling = self.decoder.smart_decode_hex(bytes.fromhex("8415214305"), "calling")
        self.assertEqual(calling["number"], "12345")
        self.assertEqual(calling["presentation"], 1)
        self.assertEqual(calling["screening"], 1)
        self.assertEqual(self.decoder.smart_decode_hex(bytes.fromhex("84102143f5"), "called"), "hex:84102143f5")
        even = self.decoder.smart_decode_hex(bytes.fromhex("04102143"), "called")
        self.assertEqual(even["number"], "1234")

    def test_imei_not_preempted_by_imsi(self):
        self.decoder.field_formats = {"equipment": "imei-tbcd"}
        data = bytes.fromhex("94104502237315f8")
        self.assertEqual(self.decoder.smart_decode_hex(data, "equipment"), "IMEI:490154203237518")

    def test_format_dispatch_precedes_printable_bytes_and_nested_asn(self):
        self.decoder.field_formats = {"tbcd": "tbcd-digits", "digits": "ascii-digits", "label": "utf-8"}
        with patch.object(self.decoder, "try_asn1_decode_bytes", side_effect=AssertionError("Unexpected probe")):
            self.assertEqual(self.decoder.make_json_safe(b"12", context_path="tbcd", spec=object(),
                             asn_try_nested=True, nested_types=["Any"]), "1323")
            self.assertEqual(self.decoder.make_json_safe(b"12", context_path="digits"), "12")
            self.assertEqual(self.decoder.make_json_safe(b"hello", context_path="label"), "hello")
            self.assertEqual(self.decoder.make_json_safe(b"hello", context_path="digits"), "hex:68656c6c6f")

    def test_unknown_fields_do_not_trigger_generic_asn_probes(self):
        with patch.object(self.decoder, "try_asn1_decode_bytes", side_effect=AssertionError("Unexpected probe")):
            for path in ("identity", "cccontents.identity"):
                self.assertEqual(self.decoder.make_json_safe(b"\x04\x01A", context_path=path,
                                 spec=object(), asn_try_nested=True), "hex:040141")

    def test_choice_names_and_paths_survive_der_to_json(self):
        self.decoder.field_formats = {"identity.imsi": "imsi-tbcd"}
        self.decoder.spec = asn1tools.compile_string('''
            Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            Record ::= SEQUENCE { identity CHOICE { imsi OCTET STRING, opaque OCTET STRING } }
            END
        ''', 'der')
        value = {"identity": ("imsi", bytes.fromhex("19325476981032f4"))}
        wire = self.decoder.spec.encode("Record", value)
        success, result = self.decoder.process_bytes(wire, roots="Record")
        self.assertTrue(success)
        self.assertEqual(result["content"]["identity"], ["imsi", "912345678901234"])

    def test_constructor_validates_configuration(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            decoder = ASN1Decoder("unused", {"target.imsi": "imsi-tbcd"})
            self.assertEqual(decoder.field_formats["target.imsi"], "imsi-tbcd")
            with self.assertRaises(ValueError):
                ASN1Decoder("unused", {"target.imsi": "guess"})

    def test_builtin_etsi_identity_fields_without_configuration(self):
        record = {"partyInformation": [{"partyIdentity": {
            "imsi": bytes.fromhex("19325476981032f4"),
            "imei": bytes.fromhex("94104502237315f8"),
            "msISDN": bytes.fromhex("912143f5"),
            "e164-Format": bytes.fromhex("8415214305"),
            "sip-uri": b"sip:alice@example.org",
            "tel-url": b"tel:+12345",
        }}]}
        result = self.decoder.make_json_safe(record)["partyInformation"][0]["partyIdentity"]
        self.assertEqual(result["imsi"], "912345678901234")
        self.assertEqual(result["imei"], "IMEI:490154203237518")
        self.assertEqual(result["msISDN"]["number"], "12345")
        self.assertEqual(result["e164-Format"]["number"], "12345")
        self.assertEqual(result["sip-uri"], "sip:alice@example.org")
        self.assertEqual(result["tel-url"], "tel:+12345")

    def test_builtin_choice_formats_and_unknown_alternatives(self):
        for name in ("callingPartyNumber", "calledPartyNumber"):
            for fmt, wire in (("iSUP-Format", "8410214305"), ("mAP-Format", "912143f5")):
                with self.subTest(name=name, fmt=fmt):
                    record = {name: (fmt, bytes.fromhex(wire))}
                    result = self.decoder.make_json_safe(record)[name]
                    self.assertEqual(result[0], fmt)
                    self.assertEqual(result[1]["number"], "12345")
            record = {name: ("dSS1-Format", b"\x81\x31\x32")}
            self.assertEqual(self.decoder.make_json_safe(record)[name][1]['number'], '12')
            record = {name: ('unrecognized-Format', b'\x81\x31\x32')}
            self.assertEqual(self.decoder.make_json_safe(record)[name][1], 'hex:813132')

    def test_builtin_scope_does_not_match_similar_fields(self):
        wire = bytes.fromhex("19325476981032f4")
        for path in ("imsi", "other.imsi", "partyIdentity.imsiHash", "notpartyIdentity.imsi",
                     "partyIdentity.IMSI", "partyIdentity.imsi.extra"):
            self.assertEqual(self.decoder.smart_decode_hex(wire, path), "hex:" + wire.hex())

    def test_exact_overrides_win_over_builtins_including_hex(self):
        self.decoder.field_formats = {"partyIdentity.imsi": "ascii-digits",
                                      "partyIdentity.msISDN": "hex"}
        self.assertEqual(self.decoder.make_json_safe(b"123456", context_path="partyIdentity.imsi"), "123456")
        self.assertEqual(self.decoder.make_json_safe(bytes.fromhex("912143f5"),
                         context_path="partyIdentity.msISDN"), "hex:912143f5")
        self.assertEqual(self.decoder.smart_decode_hex(bytes.fromhex("f12345"),
                         "outer.partyIdentity.imsi"), "hex:f12345")

    def test_builtin_dispatch_precedes_printable_and_nested_probing(self):
        with patch.object(self.decoder, "try_asn1_decode_bytes", side_effect=AssertionError("Unexpected probe")):
            result = self.decoder.make_json_safe(b"123", context_path="partyIdentity.imsi",
                         spec=object(), asn_try_nested=True, nested_types=["Any"])
        self.assertEqual(result, "132333")

    def test_builtin_choices_through_der_without_manual_mappings(self):
        self.decoder.spec = asn1tools.compile_string('''
            Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            Record ::= SEQUENCE { partyIdentity SEQUENCE {
                imsi OCTET STRING,
                callingPartyNumber CHOICE { iSUP-Format OCTET STRING, mAP-Format OCTET STRING }
            } }
            END
        ''', 'der')
        value = {"partyIdentity": {"imsi": bytes.fromhex("19325476981032f4"),
                 "callingPartyNumber": ("mAP-Format", bytes.fromhex("912143f5"))}}
        wire = self.decoder.spec.encode("Record", value)
        success, result = self.decoder.process_bytes(wire, roots="Record")
        self.assertTrue(success)
        identity = result["content"]["partyIdentity"]
        self.assertEqual(identity["imsi"], "912345678901234")
        self.assertEqual(identity["callingPartyNumber"][1]["number"], "12345")


if __name__ == "__main__":
    unittest.main()
