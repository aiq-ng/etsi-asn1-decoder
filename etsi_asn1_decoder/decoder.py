#!/usr/bin/env python3
import os
import json
import argparse
import ipaddress
import uuid
from datetime import datetime, timezone
import asn1tools
from typing import Any, Optional, Tuple
import orjson
import re
from .sms import decode_tpdu, decode_gsm7, reassemble_sms
from .field_formats import builtin_field_format
from collections.abc import Mapping


class ASN1Decoder:
    def __init__(self, asn_dir: str, field_formats: Optional[dict] = None,
                 *, encoding: Optional[str] = None, use_builtin_formats: bool = True):
        if field_formats is not None and not isinstance(field_formats, Mapping):
            raise ValueError("field_formats must be a mapping of exact paths to formats")
        if not isinstance(use_builtin_formats, bool):
            raise ValueError("use_builtin_formats must be a boolean")
        self.field_formats = dict(field_formats or {})
        self.use_builtin_formats = use_builtin_formats
        supported = {"tbcd-digits", "imsi-tbcd", "imei-tbcd", "map-address",
                     "isup-called", "isup-calling", "ascii-digits", "ascii-text", "utf-8",
                     "ipv4", "ipv6", "uuid", "uint-be", "hex"}
        for path, fmt in self.field_formats.items():
            if not isinstance(path, str) or not isinstance(fmt, str) or fmt not in supported:
                raise ValueError(f"Invalid field format mapping: {path!r}: {fmt!r}")
        self.asn_dir = asn_dir
        self._specs = {}
        # Preserve subclass compilation defaults when no codec was requested.
        self.spec = (self.compile_asn1_from_dir(asn_dir) if encoding is None
                     else self._spec_for_encoding(encoding))

    def _spec_for_encoding(self, encoding):
        if encoding is None:
            return self.spec
        if encoding not in ("ber", "der"):
            raise ValueError("encoding must be 'ber' or 'der'")
        if encoding not in self._specs:
            self._specs[encoding] = self.compile_asn1_from_dir(self.asn_dir, encoding=encoding)
        return self._specs[encoding]

    def decode_bcd_phone_number(self, data: bytes) -> Optional[str]:
        """Decode decimal TBCD only; F is allowed only as final high filler."""
        if not data:
            return None
        digits = []
        for i, byte in enumerate(data):
            low, high = byte & 15, byte >> 4
            if low > 9:
                return None
            digits.append(str(low))
            if high == 15 and i == len(data) - 1:
                continue
            if high > 9:
                return None
            digits.append(str(high))
        return ''.join(digits)

    def decode_map_format_number(self, data: bytes) -> Optional[dict]:
        """Decode MAP AddressString: one TON/NPI octet followed by TBCD."""
        if not 2 <= len(data) <= 20 or not data[0] & 0x80:
            return None
        number = self.decode_bcd_phone_number(data[1:])
        if number is None:
            return None
        return {"number": number, "nature_of_address": (data[0] >> 4) & 7,
                "numbering_plan": data[0] & 15, "raw_hex": data.hex()}

    def decode_e164_format(self, data: bytes) -> Optional[dict]:
        """Legacy alias for MAP AddressString, not an ISUP decoder.

        E.164 specifies a numbering plan, not a unique octet encoding.
        """
        return self.decode_map_format_number(data)

    def decode_isup_number(self, data: bytes, calling: bool = False) -> Optional[dict]:
        """Decode Q.763 parameter contents (without tag/length), decimal digits."""
        if len(data) < 3:
            return None
        odd = bool(data[0] & 0x80)
        digits = []
        for byte in data[2:]:
            digits.extend((byte & 15, byte >> 4))
        if odd:
            if digits.pop() != 0:
                return None
        if any(d > 9 for d in digits):
            return None
        result = {"number": ''.join(map(str, digits)),
                  "nature_of_address": data[0] & 0x7F,
                  "numbering_plan": (data[1] >> 4) & 7, "raw_hex": data.hex()}
        if calling:
            result.update(presentation=(data[1] >> 2) & 3, screening=data[1] & 3)
        return result

    def decode_imsi(self, data: bytes) -> Optional[str]:
        """Decode MAP IMSI TBCD; no NAS mobile-identity header is present."""
        if not 3 <= len(data) <= 8:
            return None
        digits = self.decode_bcd_phone_number(data)
        return digits if digits is not None and 5 <= len(digits) <= 15 else None

    def decode_imei(self, data: bytes) -> Optional[str]:
        """Decode a 15-digit TBCD IMEI, without a mobile-identity header."""
        if len(data) != 8:
            return None
        digits = self.decode_bcd_phone_number(data)
        return "IMEI:" + digits if digits is not None and len(digits) == 15 else None

    def decode_global_cell_id(self, data: bytes) -> Optional[dict]:
        """
        Decode Global Cell ID (5-7 octets per 3GPP TS 29.002).
        Format: MCC (3 digits) + MNC (2-3 digits) + LAC (2 octets) + CI (2 octets)
        """
        if len(data) < 5:
            return None
        
        # MCC and MNC are BCD encoded in first 3 bytes
        # Byte 0: MCC digit 2, MCC digit 1
        # Byte 1: MNC digit 3, MCC digit 3
        # Byte 2: MNC digit 2, MNC digit 1
        
        mcc_mnc = data[:3]
        lac = int.from_bytes(data[3:5], 'big') if len(data) >= 5 else None
        ci = int.from_bytes(data[5:7], 'big') if len(data) >= 7 else None
        
        # Decode MCC/MNC
        mcc = f"{mcc_mnc[0] & 0x0F}{(mcc_mnc[0] >> 4) & 0x0F}{mcc_mnc[1] & 0x0F}"
        mnc_digit3 = (mcc_mnc[1] >> 4) & 0x0F
        mnc_base = f"{mcc_mnc[2] & 0x0F}{(mcc_mnc[2] >> 4) & 0x0F}"
        
        if mnc_digit3 == 0xF:
            mnc = mnc_base  # 2-digit MNC
        else:
            mnc = f"{mnc_digit3}{mnc_base}"  # 3-digit MNC
        
        result = {
            "MCC": mcc,
            "MNC": mnc,
            "raw_hex": data.hex()
        }
        if lac is not None:
            result["LAC"] = str(lac)
        if ci is not None:
            result["CellID"] = str(ci)
        
        return result

    def decode_plmn(self, data: bytes) -> Optional[dict]:
        """
        Decode a 3-octet PLMN identifier (MCC+MNC) in BCD format.
        """
        if len(data) != 3:
            return None

        mcc_digit1 = data[0] & 0x0F
        mcc_digit2 = (data[0] >> 4) & 0x0F
        mcc_digit3 = data[1] & 0x0F

        mnc_digit3 = (data[1] >> 4) & 0x0F
        mnc_digit1 = data[2] & 0x0F
        mnc_digit2 = (data[2] >> 4) & 0x0F

        digits = [mcc_digit1, mcc_digit2, mcc_digit3, mnc_digit1, mnc_digit2]
        if any(d > 9 for d in digits if d != 0xF):
            return None

        mcc = f"{mcc_digit1}{mcc_digit2}{mcc_digit3}"
        if mnc_digit3 == 0xF:
            mnc = f"{mnc_digit1}{mnc_digit2}"
        else:
            if mnc_digit3 > 9:
                return None
            mnc = f"{mnc_digit1}{mnc_digit2}{mnc_digit3}"

        return {
            "type": "plmn",
            "MCC": mcc,
            "MNC": mnc,
            "raw_hex": data.hex()
        }

    def decode_ip_address(self, data: bytes) -> Optional[dict]:
        """
        Decode IPv4/IPv6 binary addresses.
        """
        try:
            if len(data) == 4:
                ip = ipaddress.IPv4Address(data)
                return {"type": "ipv4", "address": str(ip), "raw_hex": data.hex()}
            if len(data) == 16:
                ip = ipaddress.IPv6Address(data)
                return {"type": "ipv6", "address": ip.compressed, "full": ip.exploded, "raw_hex": data.hex()}
        except Exception:
            return None
        return None

    def decode_uuid_bytes(self, data: bytes) -> Optional[dict]:
        """
        Interpret 16 octets as UUID/GUID.
        """
        if len(data) != 16:
            return None
        try:
            u = uuid.UUID(bytes=data)
        except Exception:
            return None
        return {"type": "uuid", "value": str(u), "raw_hex": data.hex()}

    def decode_unix_timestamp(self, data: bytes) -> Optional[dict]:
        """
        Interpret 4 or 8 byte integers as Unix timestamps (seconds, ms, or µs).
        """
        if len(data) not in (4, 8):
            return None

        value = int.from_bytes(data, byteorder="big", signed=False)
        min_seconds = 946684800  # 2000-01-01
        max_seconds = 4102444800  # 2100-01-01

        def build(seconds: float, precision: str):
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            return {
                "type": "unix_timestamp",
                "precision": precision,
                "iso8601": dt.isoformat(),
                "value": value,
                "raw_hex": data.hex()
            }

        if min_seconds <= value <= max_seconds:
            return build(value, "seconds")

        milliseconds = value / 1000.0
        if min_seconds <= milliseconds <= max_seconds:
            return build(milliseconds, "milliseconds")

        microseconds = value / 1_000_000.0
        if min_seconds <= microseconds <= max_seconds:
            return build(microseconds, "microseconds")

        return None

    def decode_unsigned_identifier(self, data: bytes, max_len: int = 8) -> Optional[dict]:
        """
        Treat short byte blobs as unsigned integers (common for identifiers/counters).
        """
        if not data or len(data) > max_len:
            return None
        value = int.from_bytes(data, byteorder="big", signed=False)
        return {
            "type": "uint",
            "bytes": len(data),
            "int": value,
            "hex": data.hex()
        }

    def decode_communication_identifier_blob(self, data: bytes) -> Optional[dict]:
        """
        Attempt to decode a raw OCTET STRING that carries an ETSI/3GPP
        CommunicationIdentifier-style blob where the last 4 bytes are a CIN
        (Communication Identity Number) and the preceding bytes contain the
        network identifier metadata.
        """
        if len(data) < 4:
            return None

        cin_bytes = data[-4:]
        cin_value = int.from_bytes(cin_bytes, byteorder="big", signed=False)
        cin_ascii_digits = ''.join(chr(b) for b in cin_bytes if 0x30 <= b <= 0x39)

        decoded = {
            "format": "etsi_communication_identifier",
            "raw_hex": data.hex(),
            "cin": {
                "int": cin_value,
                "hex": cin_bytes.hex()
            }
        }

        if len(cin_ascii_digits) == len(cin_bytes):
            decoded["cin"]["ascii_digits"] = cin_ascii_digits

        prefix = data[:-4]
        if prefix:
            decoded["network_identifier_blob_hex"] = prefix.hex()
            decoded["network_identifier_blob_length"] = len(prefix)

            if self.is_printable_ascii(prefix):
                try:
                    ascii_value = prefix.decode('ascii').strip('\x00')
                    if ascii_value:
                        decoded["network_identifier_ascii"] = ascii_value
                except Exception:
                    pass

            # Heuristic split: first byte = network identifier, second = profile bits,
            # remaining bytes = internal correlation reference.
            if 1 <= len(prefix) <= 4:
                decoded["network_identifier"] = prefix[0]

                if len(prefix) >= 2:
                    profile_bits = prefix[1]
                    decoded["profile_specific_bits"] = {
                        "value": profile_bits,
                        "binary": f"{profile_bits:08b}"
                    }

                if len(prefix) >= 3:
                    internal_bytes = prefix[2:]
                    if internal_bytes:
                        internal_value = int.from_bytes(internal_bytes, byteorder="big", signed=False)
                        decoded["internal_correlation"] = {
                            "int": internal_value,
                            "decimal": str(internal_value),
                            "hex": internal_bytes.hex(),
                            "bytes": len(internal_bytes)
                        }

        return decoded

    def decode_sms_pdu(self, data: bytes, direction: Optional[str] = None,
                       report_kind: Optional[str] = None) -> Optional[dict]:
        """Decode a bare SMS TPDU; optionally supply direction and RP ACK/error.

        Invalid data returns None. Ambiguous layouts return SMS-AMBIGUOUS.
        See sms.decode_tpdu for accepted context values.
        """
        return decode_tpdu(data, direction=direction, report_kind=report_kind)

    def reassemble_sms(self, parts) -> dict:
        """Reassemble decoded segments selected from one conversation/message."""
        return reassemble_sms(parts)

    def decode_gsm7bit(self, data: bytes, length: int, start_septet: int = 0) -> Optional[str]:
        """Decode packed GSM-7 including extensions; reject truncated data."""
        try:
            return decode_gsm7(data, length, start_septet)
        except ValueError:
            return None

    def is_cc_context(self, context: str) -> bool:
        """
        Identify ccContent/CC-PDU like fields from the context path.
        """
        ctx = context.lower()
        cc_markers = [
            "cccontents",
            "cc-content",
            "cc_pdu",
            "cc-pdu",
            "ccpdu",
            "callcontent"
        ]
        return any(marker in ctx for marker in cc_markers)

    def _collect_type_names(self, spec) -> list:
        """
        Collect all visible type names from an asn1tools spec object.
        """
        names = []
        for attr in ("types", "_types"):
            val = getattr(spec, attr, None)
            if isinstance(val, dict):
                names.extend(val.keys())

        modules = getattr(spec, "modules", None)
        if isinstance(modules, dict):
            for mod_types in modules.values():
                if isinstance(mod_types, dict):
                    names.extend(mod_types.keys())

        # Preserve order but drop duplicates
        seen = set()
        uniq = []
        for name in names:
            if name not in seen:
                uniq.append(name)
                seen.add(name)
        return uniq

    def _cc_type_candidates(self, spec, nested_types=None) -> list:
        """
        Build a prioritized list of ASN.1 types that look like CC/CC-PDU payloads.
        """
        candidates = []
        if nested_types:
            candidates.extend(nested_types)

        # Commonly used names across ETSI LI CC specs
        candidates.extend([
            "CC-PDU",
            "CC_PDU",
            "CCPDU",
            "CC-Content",
            "CCContent",
            "CC-Content-WithSessionData",
            "CC-Content-With-Session-Data"
        ])

        # Add anything in the spec that hints at CC/CallContent
        for name in self._collect_type_names(spec):
            lname = name.lower()
            if "cc" in lname and ("pdu" in lname or "content" in lname):
                if name not in candidates:
                    candidates.append(name)

        return candidates

    def _field_format(self, context: str) -> Optional[str]:
        overrides = getattr(self, "field_formats", {})
        if context in overrides:
            return overrides[context]
        if getattr(self, "use_builtin_formats", True):
            return builtin_field_format(context)
        return None

    def smart_decode_hex(self, data: bytes, context: str = "") -> Any:
        """Decode only the format assigned to this exact field path.

        Explicit overrides precede known ETSI parent/field mappings.
        Unmapped or invalid fields retain hex. A failed decoder never falls
        through to another format. SMS content keeps its dedicated TPDU path.
        """
        raw = "hex:" + data.hex()
        fmt = self._field_format(context)
        if fmt is not None:
            decoders = {
                "tbcd-digits": self.decode_bcd_phone_number,
                "imsi-tbcd": self.decode_imsi,
                "imei-tbcd": self.decode_imei,
                "map-address": self.decode_map_format_number,
                "isup-called": self.decode_isup_number,
                "isup-calling": lambda value: self.decode_isup_number(value, calling=True),
                "ipv4": lambda value: self.decode_ip_address(value) if len(value) == 4 else None,
                "ipv6": lambda value: self.decode_ip_address(value) if len(value) == 16 else None,
                "uuid": self.decode_uuid_bytes,
                "uint-be": self.decode_unsigned_identifier,
                "hex": lambda value: None,
                "utf-8": lambda value: value.decode("utf-8"),
                "ascii-text": lambda value: value.decode("ascii") if value and all(32 <= b <= 126 for b in value) else None,
                "ascii-digits": lambda value: value.decode("ascii") if value and all(48 <= b <= 57 for b in value) else None,
            }
            if fmt not in decoders:
                raise ValueError(f"Unknown field format: {fmt!r}")
            try:
                result = decoders[fmt](data)
            except ValueError:
                return raw
            return result if result is not None else raw
        fields = context.lower().split(".")
        if fields[-1] == "content" and any(f in ("sms", "sms-contents") for f in fields[:-1]):
            result = self.decode_sms_pdu(data)
            return {"decoded_sms": result} if result else raw
        return raw

    def is_printable_ascii(self, b: bytes) -> bool:
        """Return True if bytes decode to UTF-8 and contain only printable characters and whitespace."""
        try:
            s = b.decode('utf-8')
        except Exception:
            return False
        # Accept common printable range plus newline/tab
        return all((31 < ord(ch) < 127) or ch in '\r\n\t' for ch in s)

    def looks_like_readable_text(self, text: str, threshold: float = 0.7) -> bool:
        """
        Heuristic: ensure decoded text contains a high fraction of printable characters.
        Helps suppress random-looking output when payload isn't actually text.
        """
        if not text:
            return False
        printable = sum(1 for ch in text if (ch.isprintable() and ch not in '\x0b\x0c') or ch in '\r\n\t')
        return (printable / len(text)) >= threshold

    def try_asn1_decode_bytes(self, spec, data: bytes, types_to_try: Optional[list] = None):
        """
        Try to decode `data` using ASN.1 `spec` for each type in types_to_try.
        Returns (type_name, decoded_obj) on first success, otherwise (None, exception_of_last_try).
        """
        last_exc = None

        # Build list of type names to try if not provided.
        if types_to_try is None:
            # Try to discover type names from the compiled spec.
            # Most asn1tools.Spec objects expose .types or ._types; we'll attempt common attributes.
            type_names = []
            # try several attributes defensively
            for attr in ('types', '_types', '_spec', 'all_types'):
                attr_val = getattr(spec, attr, None)
                if isinstance(attr_val, dict):
                    type_names = list(attr_val.keys())
                    break
                # spec._spec is sometimes a dict mapping module->types
                if isinstance(attr_val, (list, tuple)):
                    # skip
                    continue
                if isinstance(attr_val, dict):
                    # unlikely reached
                    type_names = list(attr_val.keys())
                    break
            # If nothing found, fall back to a small reasonable set (user will usually pass --roots)
            if not type_names:
                # best-effort defaults
                type_names = ['IRIsContent', 'IRIRecord', 'IRI-Begin', 'IRI-Continue', 'IRI-End', 'IRI', 'PS-PDU']
        else:
            type_names = types_to_try

        # Try each type
        for tname in type_names:
            try:
                decoded = self._decode_complete(spec, tname, data)
                # ANY can return the original encoded bytes; probing it again
                # would recurse forever without adding information.
                if isinstance(decoded, (bytes, bytearray)) and decoded == data:
                    continue
                return tname, decoded
            except Exception as e:
                last_exc = e

        return None, last_exc

    def make_json_safe(self, obj: Any, spec=None, asn_try_nested=False, nested_types=None, context_path: str = "") -> Any:
        """
        Convert decoded ASN.1 object (from asn1tools) into JSON-safe representation.
        - bytes/bytearray => exact configured format, SMS TPDU, or hex:"..."
        - nested ASN.1 probing requires a CC context or explicit nested_types
        - dict/list/tuple => recursively process
        - primitives => returned as-is
        
        context_path: string representing the field path for context-aware decoding (e.g. "sMS.content")
        """
        if isinstance(obj, (bytes, bytearray)):
            b = bytes(obj)
            context_lower = context_path.lower()
            fields = context_lower.split(".")
            if (self._field_format(context_path) is not None
                    or (fields[-1] == "content" and any(f in ("sms", "sms-contents") for f in fields[:-1]))):
                return self.smart_decode_hex(b, context=context_path)

            # Probe only designated nested payloads, never arbitrary identity bytes.
            if asn_try_nested and spec is not None and (nested_types or self.is_cc_context(fields[-1])):
                # An explicit list limits probing. CC defaults must never fall
                # back to every unrelated IRI/identity type in the schema.
                candidates = nested_types or self._cc_type_candidates(spec)
                tname, decoded = self.try_asn1_decode_bytes(spec, b, types_to_try=candidates)

                if tname:
                    return {"_decoded_as": tname, "value": self.make_json_safe(decoded, spec=spec, asn_try_nested=asn_try_nested, nested_types=nested_types, context_path=context_path)}
                # else fallthrough to smart decode

            # 3) Try smart decoding based on context and patterns
            smart_result = self.smart_decode_hex(b, context=context_path)
            
            # If smart decode returned something other than plain hex, use it
            if not (isinstance(smart_result, str) and smart_result.startswith("hex:")):
                return smart_result
            
            # 4) fallback: return hex with prefix
            return smart_result


        if isinstance(obj, dict):
            return {k: self.make_json_safe(v, spec=spec, asn_try_nested=asn_try_nested, nested_types=nested_types, context_path=f"{context_path}.{k}" if context_path else k) for k, v in obj.items()}
        if isinstance(obj, tuple) and len(obj) == 2 and isinstance(obj[0], str):
            # asn1tools CHOICE: retain the alternative name in the field path.
            name, value = obj
            path = f"{context_path}.{name}" if context_path else name
            return [name, self.make_json_safe(value, spec=spec, asn_try_nested=asn_try_nested,
                    nested_types=nested_types, context_path=path)]
        if isinstance(obj, (list, tuple)):
            items = []
            for idx, v in enumerate(obj):
                next_ctx = f"{context_path}[{idx}]" if context_path else f"[{idx}]"
                items.append(self.make_json_safe(v, spec=spec, asn_try_nested=asn_try_nested, nested_types=nested_types, context_path=next_ctx))
            return items

        # ints, floats, str, bool, None are JSON serializable
        return obj

    def compile_asn1_from_dir(self, asn_dir: str, encoding: str = 'der'):
        """Compile all files in asn_dir with asn1tools and return spec."""
        files = [
            os.path.join(asn_dir, f)
            for f in os.listdir(asn_dir)
            if os.path.isfile(os.path.join(asn_dir, f))
        ]
        if not files:
            raise FileNotFoundError(f"No ASN.1 files found in {asn_dir}")
        print(f"[+] Compiling ASN.1 files ({len(files)}) from: {asn_dir} using encoding='{encoding}'")
        spec = asn1tools.compile_files(files, encoding)
        return spec

    @staticmethod
    def _has_unknown_choice(value):
        if isinstance(value, tuple) and len(value) == 2 and value == (None, None):
            return True
        if isinstance(value, dict):
            return any(ASN1Decoder._has_unknown_choice(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return any(ASN1Decoder._has_unknown_choice(v) for v in value)
        return False

    @staticmethod
    def _decode_complete(spec, root, data):
        decoded, consumed = spec.decode_with_length(root, data)
        if consumed != len(data) or consumed == 0:
            raise ValueError(f"{root} consumed {consumed} of {len(data)} bytes; expected one complete PDU")
        if ASN1Decoder._has_unknown_choice(decoded):
            raise ValueError(f"{root} contains an unsupported ASN.1 CHOICE alternative")
        return decoded

    def try_decode_file(self, spec, candidate_roots, data):
        """
        Try each root type until one succeeds. Returns (root_used, decoded) or (None, exception).
        """
        last_exc = None
        for root in candidate_roots:
            try:
                decoded = self._decode_complete(spec, root, data)
                return root, decoded
            except Exception as e:
                last_exc = e
        return None, last_exc

    # Process a single file
    # Returns (status, result)
    def process_bytes(self, data, roots='', encoding=None, asn_try_nested=True, nested_types=None) -> Tuple[bool, Any]:
        """Decode one complete PDU; concatenated PDUs require caller framing."""
        spec = self._spec_for_encoding(encoding)
        candidate_roots = [r.strip() for r in roots.split(',') if r.strip()]
        if not candidate_roots:
            candidate_roots = ['IRIsContent', 'IRIRecord', 'IRI-Begin', 'IRI-Continue', 'IRI-End', 'IRI', 'PS-PDU']

        nested_types_list = None
        if nested_types:
            nested_types_list = [t.strip() for t in nested_types.split(',') if t.strip()]

        root_used, result = self.try_decode_file(spec, candidate_roots, data)
        
        if root_used:
            json_safe = self.make_json_safe(result, spec=spec, asn_try_nested=asn_try_nested, nested_types=nested_types_list)
            return True, {
                "decoded_with_root": root_used,
                "content": json_safe
            }

        else:
            reason = f"Failed to decode \n\n" + \
                     "Tried roots: " + ", ".join(candidate_roots) + "\n\n" + \
                     "Exception:\n" + repr(result) + "\n\n" + \
                     "Exception (str):\n" + str(result) + "\n"
            
            return False, reason
        
    def process(self, input_file, roots='', encoding=None, asn_try_nested=True, nested_types=None) -> Tuple[bool, Any]:
        with open(input_file, 'rb') as f:
            data = f.read()
        return self.process_bytes(data, roots=roots, encoding=encoding, asn_try_nested=asn_try_nested, nested_types=nested_types)

    def process_dir(self, input_dir, output_dir, roots='', encoding=None, save_raw_on_fail=True, asn_try_nested=True, nested_types=None):
        os.makedirs(output_dir, exist_ok=True)

        candidate_roots = [r.strip() for r in roots.split(',') if r.strip()]
        if not candidate_roots:
            candidate_roots = ['IRIsContent', 'IRIRecord', 'IRI-Begin', 'IRI-Continue', 'IRI-End', 'IRI', 'PS-PDU']

        print(f"[+] Candidate root types: {candidate_roots}")
        print(f"[+] Nested ASN.1 probing of bytes is {'ENABLED' if asn_try_nested else 'DISABLED'}")

        for entry in sorted(os.listdir(input_dir)):
            fullpath = os.path.join(input_dir, entry)
            if not os.path.isfile(fullpath):
                continue

            with open(fullpath, 'rb') as f:
                data = f.read()

            print(f"[ ] Decoding: {entry} ({len(data)} bytes)")
            success, result = self.process_bytes(data, roots=roots, encoding=encoding,
                                                 asn_try_nested=asn_try_nested, nested_types=nested_types)

            base_name = os.path.splitext(entry)[0]
            if success:
                out_json_path = os.path.join(output_dir, base_name + ".json")
                with open(out_json_path, 'wb') as outf:
                    outf.write(orjson.dumps(result, option=orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_DATACLASS | orjson.OPT_SERIALIZE_NUMPY))

            else:
                err_path = os.path.join(output_dir, base_name + ".error.txt")
                with open(err_path, 'w', encoding='utf-8') as ef:
                    ef.write(f"Failed to decode {entry}\n\n")
                    ef.write("Tried roots: " + ", ".join(candidate_roots) + "\n\n")
                    ef.write("Exception:\n")
                    ef.write(repr(result) + "\n\n")
                    ef.write("Exception (str):\n")
                    ef.write(str(result) + "\n")
                print(f"[!] Failed: {entry} -> {err_path}")

                if save_raw_on_fail:
                    raw_path = os.path.join(output_dir, base_name + ".bin")
                    hex_path = os.path.join(output_dir, base_name + ".hex")
                    with open(raw_path, 'wb') as rb:
                        rb.write(data)
                    with open(hex_path, 'w', encoding='utf-8') as hx:
                        hx.write(data.hex())
                    print(f"[i] Saved raw and hex: {raw_path}, {hex_path}")

def main():
    parser = argparse.ArgumentParser(description="Batch decode ASN.1 DER/BER files to JSON. Nested ASN.1 decoding of bytes is optional.")
    parser.add_argument("--asn", required=True, help="Directory containing ASN.1 files")
    parser.add_argument("--input", required=True, help="Directory with binary files to decode")
    parser.add_argument("--output", required=True, help="Directory to write decoded JSON and error files")
    parser.add_argument("--roots", default="", help="Comma-separated candidate root ASN.1 types (e.g. 'IRIsContent,IRIRecord')")
    parser.add_argument("--encoding", default="der", choices=["der", "ber"], help="Encoding used when compiling the ASN.1 files")
    parser.add_argument("--no-save-raw-on-fail", dest="save_raw", action="store_false", help="Don't save raw .bin/.hex when decode fails")
    parser.add_argument("--no-nested-asn", dest="asn_try_nested", action="store_false", help="Don't attempt nested ASN.1 decoding of bytes")
    parser.add_argument("--nested-types", default="", help="If provided, comma-separated type names to try when probing bytes (limits probing scope)")
    parser.add_argument("--field-formats", help="JSON file mapping exact field paths to byte formats")
    parser.add_argument("--no-builtin-formats", dest="use_builtin_formats", action="store_false",
                        help="Disable ETSI field-format defaults; explicit --field-formats still apply")
    args = parser.parse_args()

    field_formats = None
    if args.field_formats:
        with open(args.field_formats, encoding="utf-8") as source:
            field_formats = json.load(source)
        if not isinstance(field_formats, dict):
            parser.error("--field-formats must contain a JSON object")
    decoder = ASN1Decoder(args.asn, field_formats=field_formats, encoding=args.encoding,
                          use_builtin_formats=args.use_builtin_formats)

    decoder.process_dir(args.input, args.output, args.roots, encoding=args.encoding,
                save_raw_on_fail=args.save_raw, asn_try_nested=args.asn_try_nested, nested_types=args.nested_types)


if __name__ == "__main__":
    main()
