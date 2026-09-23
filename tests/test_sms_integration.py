import unittest
from unittest.mock import patch

import asn1tools
import orjson

from etsi_asn1_decoder.decoder import ASN1Decoder
from test_sms import HELLO, EMOJI_DELIVER, EMOJI_TEXT, deliver, segment, submit


class SMSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = asn1tools.compile_string('''
            SMSFixture DEFINITIONS ::= BEGIN
                Record ::= SEQUENCE { sms SEQUENCE { content OCTET STRING } }
            END
        ''', 'der')

    def setUp(self):
        self.decoder = ASN1Decoder.__new__(ASN1Decoder)
        self.decoder.spec = self.spec

    def test_der_to_json_for_deliver_and_submit(self):
        for wire, expected in ((deliver(), "SMS-DELIVER"), (submit(), "SMS-SUBMIT")):
            encoded = self.spec.encode("Record", {"sms": {"content": wire}})
            success, result = self.decoder.process_bytes(encoded, roots="Record")
            self.assertTrue(success)
            sms = result["content"]["sms"]["content"]["decoded_sms"]
            self.assertEqual(sms["type"], expected)
            self.assertEqual(sms["message"], "hello")
            orjson.dumps(result)

    def test_reported_etsi_sms_content_decodes_to_text(self):
        record = {"sMS": {"sMS-Contents": {
            "content": EMOJI_DELIVER,
            "other-message": "undefined",
            "sms-initiator": "server",
            "transfer-status": "succeed-transfer",
        }}}
        result = self.decoder.make_json_safe(record, spec=self.spec, asn_try_nested=True)
        sms = result["sMS"]["sMS-Contents"]["content"]["decoded_sms"]
        self.assertEqual(sms["type"], "SMS-DELIVER")
        self.assertEqual(sms["message"], EMOJI_TEXT)
        self.assertEqual(orjson.loads(orjson.dumps(result)), result)

    def test_sms_context_precedes_ascii_nested_asn_and_other_heuristics(self):
        for value in (b"hello", b"\x12\x34\x56", deliver()[:-1], b""):
            with self.subTest(value=value.hex()):
                with patch.object(self.decoder, "try_asn1_decode_bytes", side_effect=AssertionError("Must not probe SMS")):
                    result = self.decoder.make_json_safe(value, spec=self.spec, asn_try_nested=True,
                                                         context_path="record.sMS.content")
                self.assertEqual(result, "hex:" + value.hex())
                self.assertEqual(self.decoder.smart_decode_hex(value, "sMS.content"), result)

    def test_ambiguity_is_visible_in_json(self):
        result = self.decoder.make_json_safe(bytes.fromhex("008000"), context_path="sMS.content")
        self.assertEqual(result["decoded_sms"]["type"], "SMS-AMBIGUOUS")

    def test_public_wrappers(self):
        self.assertEqual(self.decoder.decode_sms_pdu(submit(), "ms-to-sc")["type"], "SMS-SUBMIT")
        self.assertEqual(self.decoder.decode_sms_pdu(b"\x00\x00", "ms-to-sc", "ack")["report_kind"], "ack")
        self.assertEqual(self.decoder.decode_gsm7bit(HELLO, 5), "hello")
        self.assertIsNone(self.decoder.decode_gsm7bit(HELLO[:-1], 5))
        self.assertEqual(self.decoder.reassemble_sms([segment(2, b"B"), segment(1, b"A")])["message"], "AB")

    def test_non_sms_decoding_is_unchanged(self):
        self.assertEqual(self.decoder.make_json_safe(b"hello", context_path="name"), "hello")
        self.assertEqual(self.decoder.decode_bcd_phone_number(bytes.fromhex("2143f5")), "12345")


if __name__ == "__main__":
    unittest.main()
