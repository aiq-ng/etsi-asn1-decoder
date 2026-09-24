"""Codec, framing, nested payload, and CLI contracts shared by every profile."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from etsi_asn1_decoder.decoder import ASN1Decoder


SCHEMA = '''Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
    Record ::= SEQUENCE { lawfulInterceptionIdentifier OCTET STRING }
    Other ::= INTEGER
    UnknownChoice ::= CHOICE { known [1] INTEGER, ... }
    Container ::= SEQUENCE { item UnknownChoice }
    Wrapper ::= SEQUENCE { payload OCTET STRING }
    Anything ::= ANY
    END'''


class DecoderContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.asn = self.root / "asn"
        self.asn.mkdir()
        (self.asn / "example.asn").write_text(SCHEMA, encoding="utf-8")
        self.decoder = ASN1Decoder(str(self.asn))
        self.wire = self.decoder.spec.encode("Record", {"lawfulInterceptionIdentifier": b"TEST"})
        self.indefinite = b"\x30\x80" + self.wire[2:] + b"\x00\x00"

    def test_constructor_and_process_encoding_reach_compiler(self):
        with patch.object(ASN1Decoder, "compile_asn1_from_dir", wraps=self.decoder.compile_asn1_from_dir) as compile_schema:
            decoder = ASN1Decoder(str(self.asn), encoding="ber")
            compile_schema.assert_called_once_with(str(self.asn), encoding="ber")
            success, result = decoder.process_bytes(self.indefinite, roots="Record")
            self.assertTrue(success, result)
            decoder.process_bytes(self.wire, roots="Record", encoding="der")
            self.assertEqual(compile_schema.call_count, 2)
            self.assertEqual(compile_schema.call_args.kwargs, {"encoding": "der"})
            decoder.process_bytes(self.indefinite, roots="Record", encoding="ber")
            self.assertEqual(compile_schema.call_count, 2)

    def test_subclass_default_codec_is_preserved(self):
        class BerDecoder(ASN1Decoder):
            def compile_asn1_from_dir(inner, asn_dir, encoding="ber"):
                inner.used_encoding = encoding
                return super().compile_asn1_from_dir(asn_dir, encoding)
        decoder = BerDecoder(str(self.asn))
        self.assertEqual(decoder.used_encoding, "ber")
        self.assertTrue(decoder.process_bytes(self.indefinite, roots="Record")[0])

    def test_invalid_codec_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "encoding"):
            ASN1Decoder(str(self.asn), encoding="guess")
        with self.assertRaisesRegex(ValueError, "encoding"):
            self.decoder.process_bytes(self.wire, roots="Record", encoding="guess")

    def test_ber_indefinite_length_and_der_definite_length(self):
        for codec, wire in (("der", self.wire), ("ber", self.indefinite)):
            success, result = self.decoder.process_bytes(wire, roots="Record", encoding=codec)
            self.assertTrue(success, result)
            self.assertEqual(result["content"]["lawfulInterceptionIdentifier"], "TEST")

    def test_trailing_bytes_concatenated_pdus_and_truncation_are_not_success(self):
        for wire in (b"", b"\xff", self.wire[:-1], self.wire + b"garbage", self.wire * 2,
                     self.indefinite[:-1], self.indefinite * 2):
            with self.subTest(wire=wire.hex()):
                success, error = self.decoder.process_bytes(wire, roots="Record", encoding="ber")
                self.assertFalse(success)
                self.assertIn("Failed to decode", error)

    def test_root_fallback_requires_complete_decode(self):
        success, result = self.decoder.process_bytes(self.wire, roots="Missing,Other,Record")
        self.assertTrue(success, result)
        self.assertEqual(result["decoded_with_root"], "Record")

    def test_unknown_extension_choice_is_not_a_successful_null_record(self):
        for root, wire in (("UnknownChoice", b"\x82\x01\x00"),
                           ("Container", b"\x30\x05\xa0\x03\x82\x01\x00")):
            success, error = self.decoder.process_bytes(wire, roots=root, encoding="ber")
            self.assertFalse(success, error)
            self.assertIn("unsupported ASN.1 CHOICE", error)

    def test_nested_probes_reject_partial_or_unknown_decodes(self):
        for wire, candidate in ((self.wire + b"extra", "Record"), (b"\x82\x01\x00", "UnknownChoice")):
            result = self.decoder.make_json_safe(wire, spec=self.decoder.spec,
                         asn_try_nested=True, nested_types=[candidate], context_path="payload")
            self.assertEqual(result, "hex:" + wire.hex())

    def test_explicit_nested_types_limit_candidates_even_for_cc(self):
        with patch.object(self.decoder, "_cc_type_candidates", side_effect=AssertionError("Do not widen explicit types")):
            result = self.decoder.make_json_safe(self.wire, spec=self.decoder.spec,
                         asn_try_nested=True, nested_types=["Other"], context_path="ccContents")
        self.assertEqual(result, "hex:" + self.wire.hex())

    def test_cc_default_does_not_fall_back_to_unrelated_iri_types(self):
        result = self.decoder.make_json_safe(self.wire, spec=self.decoder.spec,
                                             asn_try_nested=True, context_path="ccContents")
        self.assertEqual(result, "hex:" + self.wire.hex())

    def test_explicit_valid_nested_payload_decodes(self):
        result = self.decoder.make_json_safe(self.wire, spec=self.decoder.spec,
                     asn_try_nested=True, nested_types=["Record"], context_path="payload")
        self.assertEqual(result, {"_decoded_as": "Record", "value": {"lawfulInterceptionIdentifier": "TEST"}})

    def test_nested_any_does_not_recurse_on_identical_bytes(self):
        result = self.decoder.make_json_safe(self.wire, spec=self.decoder.spec,
                     asn_try_nested=True, nested_types=["Anything"], context_path="payload")
        self.assertEqual(result, "hex:" + self.wire.hex())

    def test_file_and_directory_apis_share_validation_and_formats(self):
        source = self.root / "input"
        source.mkdir()
        (source / "valid.ber").write_bytes(self.indefinite)
        (source / "invalid.ber").write_bytes(self.wire * 2)
        output = self.root / "output"
        self.decoder.process_dir(str(source), str(output), roots="Record", encoding="ber")
        success, result = self.decoder.process(str(source / "valid.ber"), roots="Record", encoding="ber")
        self.assertTrue(success, result)
        self.assertEqual(json.loads((output / "valid.json").read_text()), result)
        self.assertFalse((output / "invalid.json").exists())
        self.assertTrue((output / "invalid.error.txt").is_file())
        self.assertEqual((output / "invalid.bin").read_bytes(), self.wire * 2)

    def test_cli_ber_and_profile_options(self):
        source = self.root / "input"
        source.mkdir()
        (source / "record.ber").write_bytes(self.indefinite)
        for args, expected in (([], "TEST"), (["--no-builtin-formats"], "hex:54455354")):
            output = self.root / ("raw" if args else "decoded")
            run = subprocess.run([sys.executable, "-m", "etsi_asn1_decoder.decoder",
                                  "--asn", str(self.asn), "--input", str(source), "--output", str(output),
                                  "--roots", "Record", "--encoding", "ber", *args],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("encoding='ber'", run.stdout)
            result = json.loads((output / "record.json").read_text())
            self.assertEqual(result["content"]["lawfulInterceptionIdentifier"], expected)


if __name__ == "__main__":
    unittest.main()
