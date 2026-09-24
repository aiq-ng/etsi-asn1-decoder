"""ETSI/MAP field regressions independent of a particular network operator."""
import unittest
from unittest.mock import patch

import asn1tools
import orjson

from etsi_asn1_decoder.decoder import ASN1Decoder


class NetworkLocationFormatTests(unittest.TestCase):
    def setUp(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            self.decoder = ASN1Decoder("unused")

    def test_reported_global_cell_id(self):
        result = self.decoder.make_json_safe({"locationOfTheTarget": {
            "globalCellID": bytes.fromhex("26f10375ecb2bd")}})
        self.assertEqual(result["locationOfTheTarget"]["globalCellID"], {
            "MCC": "621", "MNC": "30", "LAC": "30188", "CellID": "45757",
            "raw_hex": "26f10375ecb2bd"})

    def test_two_and_three_digit_mncs_preserve_order_and_leading_zeroes(self):
        for prefix, mcc, mnc in (("26f103", "621", "30"), ("130062", "310", "260"),
                                 ("00f110", "001", "01"), ("001100", "001", "001"),
                                 ("999999", "999", "999")):
            with self.subTest(prefix=prefix):
                plmn = self.decoder.decode_plmn(bytes.fromhex(prefix))
                result = self.decoder.smart_decode_hex(bytes.fromhex(prefix + "0000ffff"), "globalCellID")
                self.assertEqual((result["MCC"], result["MNC"]), (mcc, mnc))
                self.assertEqual((plmn["MCC"], plmn["MNC"]), (mcc, mnc))
                self.assertEqual(result["LAC"], "0")
                self.assertEqual(result["CellID"], "65535")

    def test_five_octets_have_no_invented_cell_id(self):
        self.assertEqual(self.decoder.decode_global_cell_id(bytes.fromhex("26f10375ec")),
                         {"MCC": "621", "MNC": "30", "LAC": "30188", "raw_hex": "26f10375ec"})

    def test_incomplete_or_extra_octets_are_preserved(self):
        base = bytes.fromhex("26f10375ecb2bd")
        for length in (0, 1, 2, 3, 4, 6, 8, 9, 16):
            data = (base + b"\x00" * 16)[:length]
            with self.subTest(length=length):
                self.assertIsNone(self.decoder.decode_global_cell_id(data))
                self.assertEqual(self.decoder.smart_decode_hex(data, "globalCellID"), "hex:" + data.hex())

    def test_invalid_bcd_digits_and_misplaced_filler_never_decode(self):
        base = bytes.fromhex("130062")
        for nibble in range(6):
            for value in range(10, 16):
                # High nibble of octet two is the only allowed F filler.
                if nibble == 3 and value == 15:
                    continue
                data = bytearray(base)
                byte_index, half = divmod(nibble, 2)
                shift = half * 4
                data[byte_index] = (data[byte_index] & ~(15 << shift)) | (value << shift)
                with self.subTest(nibble=nibble, value=value):
                    self.assertIsNone(self.decoder.decode_plmn(data))
                    wire = bytes(data) + b"\x00\x01\x00\x02"
                    self.assertEqual(self.decoder.smart_decode_hex(wire, "globalCellID"), "hex:" + wire.hex())

    def test_operator_identifier_is_explicit_ascii_with_lossless_fallback(self):
        for data in (b"MTN", b"OP-1", b"001", b" A "):
            result = self.decoder.make_json_safe({"network-Identifier": {"operator-Identifier": data}})
            self.assertEqual(result["network-Identifier"]["operator-Identifier"], data.decode("ascii"))
        for data in (b"", b"MTN\x00", b"\xff\x00", b"A\n"):
            self.assertEqual(self.decoder.smart_decode_hex(data, "operator-Identifier"), "hex:" + data.hex())

    def test_reported_network_element_uses_both_isup_header_octets(self):
        data = bytes.fromhex("841332843000190100")
        for field in ("network-Element-Identifier", "servingSystem"):
            result = self.decoder.make_json_safe({field: ("e164-Format", data)})[field]
            self.assertEqual(result, ["e164-Format", {
                "number": "2348030091100", "nature_of_address": 4, "numbering_plan": 1,
                "presentation": 0, "screening": 3, "raw_hex": data.hex()}])

    def test_even_isup_number_and_invalid_odd_filler(self):
        path = "network-Element-Identifier.e164-Format"
        self.assertEqual(self.decoder.smart_decode_hex(bytes.fromhex("04130021"), path)["number"], "0012")
        for data in (b"", b"\x84\x13", bytes.fromhex("84132143f5"), bytes.fromhex("04132a43")):
            self.assertEqual(self.decoder.smart_decode_hex(data, path), "hex:" + data.hex())

    def test_similar_names_and_other_choices_remain_opaque(self):
        wire = bytes.fromhex("26f10375ecb2bd")
        for path in ("cell", "globalCellId", "globalCellIDHash", "globalCellID.child", "location.eCGI"):
            self.assertEqual(self.decoder.smart_decode_hex(wire, path), "hex:" + wire.hex())
        for path in ("e164-Format", "other.e164-Format", "network-Element-Identifier.e164-format",
                     "network-Element-Identifier.x25-Format", "other.operator-IdentifierHash", "Operator-Identifier"):
            self.assertEqual(self.decoder.smart_decode_hex(b"MTN", path), "hex:4d544e")

    def test_overrides_and_disabling_defaults_work_for_all_new_mappings(self):
        for path, data in (("locationOfTheTarget.globalCellID", bytes.fromhex("26f10375ecb2bd")),
                           ("network-Identifier.operator-Identifier", b"MTN"),
                           ("network-Identifier.network-Element-Identifier.e164-Format", bytes.fromhex("8413214305"))):
            self.decoder.field_formats = {path: "hex"}
            self.assertEqual(self.decoder.smart_decode_hex(data, path), "hex:" + data.hex())
            self.decoder.field_formats = {}
            self.decoder.use_builtin_formats = False
            self.assertEqual(self.decoder.smart_decode_hex(data, path), "hex:" + data.hex())
            self.decoder.use_builtin_formats = True
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", return_value=None):
            explicit = ASN1Decoder("unused", {"custom": "map-global-cell-id"}, use_builtin_formats=False)
        self.assertEqual(explicit.smart_decode_hex(bytes.fromhex("26f10375ecb2bd"), "custom")["CellID"], "45757")

    def test_mapped_fields_precede_nested_asn_probing(self):
        with patch.object(self.decoder, "try_asn1_decode_bytes", side_effect=AssertionError("Unexpected probe")):
            result = self.decoder.make_json_safe(bytes.fromhex("26f10375ecb2bd"),
                        context_path="globalCellID", spec=object(), asn_try_nested=True, nested_types=["Any"])
            self.assertEqual(result["CellID"], "45757")

    def test_all_fields_through_ber_der_choices_and_lists(self):
        schema = '''Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            Records ::= SEQUENCE OF CHOICE { event Record }
            Record ::= SEQUENCE {
                locationOfTheTarget SEQUENCE { globalCellID OCTET STRING },
                communicationIdentifier SEQUENCE { network-Identifier SEQUENCE {
                    operator-Identifier OCTET STRING,
                    network-Element-Identifier CHOICE { e164-Format OCTET STRING, x25-Format OCTET STRING }
                } }
            }
            END'''
        wire_cgi = bytes.fromhex("26f10375ecb2bd")
        wire_number = bytes.fromhex("841332843000190100")
        values = [("event", {
            "locationOfTheTarget": {"globalCellID": wire_cgi},
            "communicationIdentifier": {"network-Identifier": {"operator-Identifier": operator,
                "network-Element-Identifier": ("e164-Format", wire_number)}}
        }) for operator in (b"MTN", b"OP-1")]
        for encoding in ("ber", "der"):
            self.decoder.spec = asn1tools.compile_string(schema, encoding)
            wire = self.decoder.spec.encode("Records", values)
            accepted, result = self.decoder.process_bytes(wire, roots="Records")
            self.assertTrue(accepted, result)
            for record, operator in zip(result["content"], ("MTN", "OP-1")):
                self.assertEqual(record[1]["locationOfTheTarget"]["globalCellID"]["CellID"], "45757")
                network = record[1]["communicationIdentifier"]["network-Identifier"]
                self.assertEqual(network["operator-Identifier"], operator)
                self.assertEqual(network["network-Element-Identifier"][1]["number"], "2348030091100")
            self.assertEqual(orjson.loads(orjson.dumps(result)), result)


if __name__ == "__main__":
    unittest.main()
