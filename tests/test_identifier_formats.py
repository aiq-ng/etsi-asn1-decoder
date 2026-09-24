"""Public, synthetic identifier vectors; no operator captures or routing rules."""
import unittest
from unittest.mock import patch

import asn1tools
import orjson

from etsi_asn1_decoder.decoder import ASN1Decoder


class IdentifierFormatTests(unittest.TestCase):
    def setUp(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            self.decoder = ASN1Decoder("unused")

    def test_liid_ascii_preserves_every_character(self):
        for value in (b"TEST", b"000123", b"A-z_09.example", b" tenant/id:001 "):
            with self.subTest(value=value):
                result = self.decoder.make_json_safe({"lawfulInterceptionIdentifier": value})
                self.assertEqual(result["lawfulInterceptionIdentifier"].encode("ascii"), value)

    def test_cin_preserves_zeros_without_numeric_coercion(self):
        for value in (b"0", b"00000000", b"00000123", b"98765432"):
            result = self.decoder.make_json_safe({"communicationIdentifier": {
                "communication-Identity-Number": value}})
            self.assertEqual(result["communicationIdentifier"]["communication-Identity-Number"],
                             value.decode("ascii"))

    def test_all_single_octets_follow_the_selected_format(self):
        for number in range(256):
            data = bytes([number])
            raw = "hex:" + data.hex()
            with self.subTest(number=number):
                self.assertEqual(self.decoder.smart_decode_hex(data, "lawfulInterceptionIdentifier"),
                                 chr(number) if 32 <= number <= 126 else raw)
                self.assertEqual(self.decoder.smart_decode_hex(data, "communication-Identity-Number"),
                                 chr(number) if 48 <= number <= 57 else raw)

    def test_binary_empty_control_and_non_ascii_values_are_lossless(self):
        for path in ("lawfulInterceptionIdentifier", "communication-Identity-Number"):
            for data in (b"", b"\x00TEST", b"TEST\x00", b"12\n", b"12\t", b"\x7f",
                         bytes(range(256)), "é".encode("utf-8")):
                with self.subTest(path=path, data=data):
                    result = self.decoder.make_json_safe(bytearray(data), context_path=path)
                    self.assertEqual(result, "hex:" + data.hex())
                    self.assertEqual(bytes.fromhex(result[4:]), data)

    def test_similar_names_ancestors_and_unmapped_fields_stay_hex(self):
        for path in ("liid", "cin", "identifier", "unrelated", "LawfulInterceptionIdentifier",
                     "lawfulInterceptionIdentifierHash", "lawfulInterceptionIdentifier.extra",
                     "communication-identity-number", "communication-Identity-NumberHash"):
            self.assertEqual(self.decoder.smart_decode_hex(b"TEST", path), "hex:54455354")

    def test_standalone_roots_choices_and_lists_share_the_contract(self):
        for root in ("iRI-Begin-record", "iRI-Continue-record", "iRI-End-record", "iRI-Report-record"):
            records = {"records": [(root, {"lawfulInterceptionIdentifier": b"TEST",
                                          "communicationIdentifier": {
                                              "communication-Identity-Number": b"00123"}})]}
            result = self.decoder.make_json_safe(records)["records"][0]
            self.assertEqual(result[0], root)
            self.assertEqual(result[1]["lawfulInterceptionIdentifier"], "TEST")
            self.assertEqual(result[1]["communicationIdentifier"]["communication-Identity-Number"], "00123")
        self.assertEqual(self.decoder.make_json_safe({"communication-Identity-Number": b"0001"}),
                         {"communication-Identity-Number": "0001"})

    def test_native_asn_strings_and_integers_are_not_reinterpreted(self):
        record = {"lawfulInterceptionIdentifier": "é", "communication-Identity-Number": 123}
        self.assertEqual(self.decoder.make_json_safe(record), record)

    def test_profiles_override_defaults_without_mutating_other_instances(self):
        mappings = {"lawfulInterceptionIdentifier": "hex", "communication-Identity-Number": "ascii-text"}
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            custom = ASN1Decoder("unused", mappings)
        mappings["lawfulInterceptionIdentifier"] = "utf-8"
        self.assertEqual(custom.smart_decode_hex(b"TEST", "lawfulInterceptionIdentifier"), "hex:54455354")
        self.assertEqual(custom.smart_decode_hex(b"call-A", "communication-Identity-Number"), "call-A")
        self.assertEqual(self.decoder.smart_decode_hex(b"TEST", "lawfulInterceptionIdentifier"), "TEST")
        self.assertEqual(self.decoder.smart_decode_hex(b"call-A", "communication-Identity-Number"), "hex:63616c6c2d41")
        custom.field_formats = {"lawfulInterceptionIdentifier": "utf-8"}
        self.assertEqual(custom.smart_decode_hex("é".encode(), "lawfulInterceptionIdentifier"), "é")

    def test_disabling_builtins_retains_explicit_overrides(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            decoder = ASN1Decoder("unused", {"custom": "ascii-text"}, use_builtin_formats=False)
        self.assertEqual(decoder.make_json_safe({"lawfulInterceptionIdentifier": b"TEST",
                                                "custom": b"vendor ID"}),
                         {"lawfulInterceptionIdentifier": "hex:54455354", "custom": "vendor ID"})
        self.assertEqual(decoder.smart_decode_hex(b"123", "partyIdentity.imsi"), "hex:313233")

    def test_opaque_correlation_bytes_need_an_explicit_text_profile(self):
        path = "iRI-Report-record.ePSCorrelationNumber"
        wire = b"session-1"
        self.assertEqual(self.decoder.smart_decode_hex(wire, path), "hex:" + wire.hex())
        self.decoder.field_formats[path] = "ascii-text"
        self.assertEqual(self.decoder.smart_decode_hex(wire, path), "session-1")
        binary = b"\x00\xff\x01\x02"
        self.assertEqual(self.decoder.smart_decode_hex(binary, path), "hex:" + binary.hex())

    def test_invalid_profiles_fail_before_compiling(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir") as compile_schema:
            for mappings in ([], "guess", {"field": []}, {1: "hex"}, {"field": None}):
                with self.subTest(mappings=mappings), self.assertRaises(ValueError):
                    ASN1Decoder("unused", mappings)
            with self.assertRaises(ValueError):
                ASN1Decoder("unused", use_builtin_formats="false")
            compile_schema.assert_not_called()

    def test_identifiers_through_ber_and_der_without_profile_configuration(self):
        schema = '''Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            Records ::= SEQUENCE OF CHOICE { event Record }
            Record ::= SEQUENCE {
                lawfulInterceptionIdentifier OCTET STRING,
                communicationIdentifier SEQUENCE { communication-Identity-Number OCTET STRING },
                unrelated OCTET STRING
            }
            END'''
        values = [("event", {"lawfulInterceptionIdentifier": value,
                            "communicationIdentifier": {"communication-Identity-Number": b"000123"},
                            "unrelated": b"TEST"}) for value in (b"TEST", b"00123", b"\xff\x00")]
        for encoding in ("ber", "der"):
            with self.subTest(encoding=encoding):
                self.decoder.spec = asn1tools.compile_string(schema, encoding)
                wire = self.decoder.spec.encode("Records", values)
                success, result = self.decoder.process_bytes(wire, roots="Records")
                self.assertTrue(success, result)
                records = result["content"]
                self.assertEqual([r[1]["lawfulInterceptionIdentifier"] for r in records],
                                 ["TEST", "00123", "hex:ff00"])
                for record in records:
                    self.assertEqual(record[1]["communicationIdentifier"]["communication-Identity-Number"], "000123")
                    self.assertEqual(record[1]["unrelated"], "hex:54455354")
                self.assertEqual(orjson.loads(orjson.dumps(result)), result)


if __name__ == "__main__":
    unittest.main()
