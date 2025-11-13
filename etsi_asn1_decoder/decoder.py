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


class ASN1Decoder:   
    def __init__(self, asn_dir: str):
        self.spec = self.compile_asn1_from_dir(asn_dir)

    def decode_bcd_phone_number(self, data: bytes) -> Optional[str]:
        """
        Decode BCD-encoded phone number (semi-octets).
        Common in E.164 numbers, MSISDN, IMSI, etc.
        Returns decoded string or None if invalid.
        """
        if not data:
            return None
        
        digits = []
        for byte in data:
            low = byte & 0x0F
            high = (byte >> 4) & 0x0F
            
            # 0xF is filler
            if low <= 9:
                digits.append(str(low))
            elif low == 0xF:
                pass  # filler, skip
            else:
                return None  # invalid BCD
            
            if high <= 9:
                digits.append(str(high))
            elif high == 0xF:
                pass  # filler, skip
            else:
                return None  # invalid BCD
        
        return ''.join(digits) if digits else None

    def decode_e164_format(self, data: bytes) -> Optional[dict]:
        """
        Decode E.164 formatted number (ISUP calling/called party number format).
        First byte is typically nature of address indicator + numbering plan.
        Remaining bytes are BCD encoded digits.
        """
        if len(data) < 2:
            return None
        
        nature_and_plan = data[0]
        bcd_data = data[1:]
        
        number = self.decode_bcd_phone_number(bcd_data)
        if number:
            return {
                "number": number,
                "nature_of_address": (nature_and_plan >> 4) & 0x0F,
                "numbering_plan": nature_and_plan & 0x0F,
                "raw_hex": data.hex()
            }
        return None

    def decode_map_format_number(self, data: bytes) -> Optional[dict]:
        """
        Decode MAP AddressString format (3GPP TS 29.002).
        First byte: nature of address + numbering plan.
        Remaining bytes: BCD encoded digits.
        """
        return self.decode_e164_format(data)

    def decode_imsi(self, data: bytes) -> Optional[str]:
        """
        Decode IMSI (International Mobile Subscriber Identity).
        Format: 3-8 octets, BCD encoded.
        """
        if not (3 <= len(data) <= 8):
            return None
        
        # First byte has parity in bit 3 and identity type
        # For IMSI, we typically skip first nibble if it's odd parity marker
        first_byte = data[0]
        identity_type = first_byte & 0x07
        
        # Decode remaining as BCD
        imsi_digits = self.decode_bcd_phone_number(data)
        
        if imsi_digits and len(imsi_digits) >= 6:  # IMSI should be 14-15 digits
            # Remove leading digit if it's parity/filler (often '1')
            if imsi_digits[0] in ['1', '9']:
                imsi_digits = imsi_digits[1:]
            return f"IMSI:{imsi_digits}"
        
        return None

    def decode_imei(self, data: bytes) -> Optional[str]:
        """
        Decode IMEI (International Mobile Equipment Identity).
        Format: 8 octets, BCD encoded.
        """
        if len(data) != 8:
            return None
        
        imei = self.decode_bcd_phone_number(data)
        if imei and len(imei) == 15:  # IMEI is 15 digits
            return f"IMEI:{imei}"
        
        return None

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
            "decimal": str(value),
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
                "decimal": str(cin_value),
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

    def decode_sms_pdu(self, data: bytes) -> Optional[dict]:
        """
        Decode SMS-DELIVER PDU (simplified version).
        This handles the content field of SMS-report which contains SMS TPDU.
        """
        if len(data) < 2:
            return None
        
        try:
            # First byte is SMS-DELIVER message type indicator
            mti = data[0] & 0x03
            
            # For SMS-DELIVER (mti = 0x00), rough structure:
            # - Byte 0: MTI + flags
            # - Byte 1-n: Originating address (variable)
            # - Protocol ID, DCS, Timestamp, UDL, UD
            
            idx = 1
            
            # Originating address length (in digits)
            if idx >= len(data):
                return None
            oa_len = data[idx]
            idx += 1
            
            # Type of address
            if idx >= len(data):
                return None
            oa_type = data[idx]
            idx += 1
            
            # Address digits (BCD)
            oa_bytes = (oa_len + 1) // 2
            if idx + oa_bytes > len(data):
                return None
            oa_data = data[idx:idx + oa_bytes]
            originating_address = self.decode_bcd_phone_number(oa_data)
            idx += oa_bytes
            
            # PID
            if idx >= len(data):
                return None
            pid = data[idx]
            idx += 1
            
            # DCS (Data Coding Scheme)
            if idx >= len(data):
                return None
            dcs = data[idx]
            idx += 1
            
            # Timestamp (7 bytes)
            if idx + 7 > len(data):
                return None
            timestamp = data[idx:idx + 7]
            idx += 7
            
            # UDL (User Data Length)
            if idx >= len(data):
                return None
            udl = data[idx]
            idx += 1
            
            # User Data
            user_data = data[idx:]
            
            # Determine encoding from DCS
            encoding = "gsm-7bit"
            if (dcs & 0x04) == 0:
                encoding = "gsm-7bit"
            elif (dcs & 0x08):
                encoding = "ucs-2"
            else:
                encoding = "8-bit"
            
            # Try to decode user data
            message_text = None
            if encoding == "gsm-7bit":
                # GSM 7-bit decoding (simplified - doesn't handle all edge cases)
                message_text = self.decode_gsm7bit(user_data, udl)
            elif encoding == "ucs-2":
                try:
                    message_text = user_data.decode('utf-16-be')
                except:
                    pass
            elif encoding == "8-bit":
                try:
                    message_text = user_data.decode('latin1')
                except:
                    pass
            
            result = {
                "type": "SMS-DELIVER",
                "encoding": encoding,
                "raw_hex": data.hex()
            }
            
            if originating_address:
                result["originating_address"] = originating_address
            if message_text:
                result["message"] = message_text
            else:
                result["user_data_hex"] = user_data.hex()
            
            return result
        
        except Exception as e:
            return None

    def decode_gsm7bit(self, data: bytes, length: int) -> Optional[str]:
        """
        Decode GSM 7-bit packed encoding.
        length is the number of septets (7-bit characters).
        """
        GSM7_BASIC = (
            "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
            "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
        )
        
        if not data:
            return None
        
        try:
            result = []
            bit_offset = 0
            
            for i in range(length):
                byte_offset = (i * 7) // 8
                shift = (i * 7) % 8
                
                if byte_offset >= len(data):
                    break
                
                char_code = data[byte_offset] >> shift
                
                if shift > 1 and byte_offset + 1 < len(data):
                    char_code |= (data[byte_offset + 1] << (8 - shift))
                
                char_code &= 0x7F
                
                if char_code < len(GSM7_BASIC):
                    result.append(GSM7_BASIC[char_code])
                else:
                    result.append('?')
            
            return ''.join(result)
        except:
            return None

    def smart_decode_hex(self, data: bytes, context: str = "") -> Any:
        """
        Attempt to intelligently decode hex data based on context and data patterns.
        Returns decoded value or original hex string if unable to decode.
        """
        if not data:
            return "hex:"
        
        # Track what we tried
        attempts = {}
        
        # Context-based decoding
        context_lower = context.lower()
        
        # SMS content
        if "sms" in context_lower and "content" in context_lower:
            result = self.decode_sms_pdu(data)
            if result:
                return {"decoded_sms": result}
        
        # IMSI
        if "imsi" in context_lower or (3 <= len(data) <= 8):
            result = self.decode_imsi(data)
            if result:
                return result
        
        # IMEI
        if "imei" in context_lower or len(data) == 8:
            result = self.decode_imei(data)
            if result:
                return result
        
        # Global Cell ID
        if "cell" in context_lower or "gcid" in context_lower or (5 <= len(data) <= 7):
            result = self.decode_global_cell_id(data)
            if result:
                return result

        # PLMN (MCC/MNC) identifiers
        if any(kw in context_lower for kw in ["plmn", "mcc", "mnc"]):
            result = self.decode_plmn(data)
            if result:
                return result

        # IP addresses
        ip_context = (
            any(kw in context_lower for kw in [
                "ipv4", "ipv6", "ipaddress", "ip-address", "ipaddr",
                "ggsnaddress", "sgsnaddress", "mmeaddress", "mmeipaddress",
                "pdnaddress", "data-node-address", "datanodeaddress", "ipvalue"
            ])
            or ("ip" in context_lower and any(marker in context_lower for marker in ["address", "addr", "endpoint", "node", "host"]))
        )
        if ip_context:
            result = self.decode_ip_address(data)
            if result:
                return result

        # Unix timestamps
        time_keywords = ["timestamp", "time", "eventtime", "generationtime", "microsecond", "millisecond", "epoch"]
        if any(kw in context_lower for kw in time_keywords):
            result = self.decode_unix_timestamp(data)
            if result:
                return result

        # UUID/GUID
        uuid_keywords = ["uuid", "guid", "traceid", "sessionid", "transactionid", "correlationid"]
        if any(kw in context_lower for kw in uuid_keywords):
            result = self.decode_uuid_bytes(data)
            if result:
                return result

        # Generic unsigned identifiers
        id_keywords = [
            "identifier",
            "liid",
            "counter",
            "sequence",
            "seq",
            "reference",
            "correlation",
            "recordid",
            "requestid",
            "messageid",
            "userid",
            "index",
            "offset"
        ]
        if any(kw in context_lower for kw in id_keywords):
            result = self.decode_unsigned_identifier(data)
            if result:
                return result

        # Communication Identifier / CIN heuristic
        cin_keywords = [
            "cin",
            "communicationidentifier",
            "communication-identity-number",
            "communicationidentitynumber",
            "networkidentifier",
            "network-identifier",
            "internalcorrelation",
            "internal-correlation",
            "profilespecific",
            "profile-specific"
        ]
        if any(kw in context_lower for kw in cin_keywords):
            result = self.decode_communication_identifier_blob(data)
            if result:
                return result
        
        # Phone numbers (E.164 or MAP format)
        if any(kw in context_lower for kw in ["number", "msisdn", "calling", "called", "address"]):
            # Try MAP format first
            result = self.decode_map_format_number(data)
            if result:
                return result
            
            # Try E164 format
            result = self.decode_e164_format(data)
            if result:
                return result
        
        # Pattern-based detection when context is not clear
        
        # Check if it looks like a phone number (MAP/E164 format)
        if len(data) >= 2:
            result = self.decode_map_format_number(data)
            if result and result.get("number") and len(result["number"]) >= 4:
                return result
        
        # Check if it could be IMEI (8 bytes)
        if len(data) == 8:
            result = self.decode_imei(data)
            if result:
                return result
        
        # Check if it could be IMSI (3-8 bytes)
        if 3 <= len(data) <= 8:
            result = self.decode_imsi(data)
            if result:
                return result
        
        # Check if it could be Global Cell ID
        if 5 <= len(data) <= 7:
            result = self.decode_global_cell_id(data)
            if result:
                return result

        # Heuristic PLMN decoding when data is 3 bytes of BCD digits
        if len(data) == 3:
            result = self.decode_plmn(data)
            if result:
                return result

        # Check for UUIDs when data is 16 bytes and looks structured
        if len(data) == 16 and data not in (b"\x00" * 16, b"\xff" * 16):
            result = self.decode_uuid_bytes(data)
            if result:
                return result

        # Timestamp heuristic without context if bytes look like sane epoch
        if len(data) in (4, 8):
            result = self.decode_unix_timestamp(data)
            if result:
                return result
        
        # Fallback: return as hex
        return "hex:" + data.hex()

    def is_printable_ascii(self, b: bytes) -> bool:
        """Return True if bytes decode to UTF-8 and contain only printable characters and whitespace."""
        try:
            s = b.decode('utf-8')
        except Exception:
            return False
        # Accept common printable range plus newline/tab
        return all((31 < ord(ch) < 127) or ch in '\r\n\t' for ch in s)

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
                decoded = spec.decode(tname, data)
                return tname, decoded
            except Exception as e:
                last_exc = e

        return None, last_exc

    def make_json_safe(self, obj: Any, spec=None, asn_try_nested=True, nested_types=None, context_path: str = "") -> Any:
        """
        Convert decoded ASN.1 object (from asn1tools) into JSON-safe representation.
        - bytes/bytearray => check: printable string, or try nested ASN.1 decode (if spec/asn_try_nested True),
        or try smart decoding based on context, else return hex:"..."
        - dict/list/tuple => recursively process
        - primitives => returned as-is
        
        context_path: string representing the field path for context-aware decoding (e.g. "sMS.content")
        """
        if isinstance(obj, (bytes, bytearray)):
            b = bytes(obj)
            # 1) printable UTF-8?
            if self.is_printable_ascii(b):
                try:
                    return b.decode('utf-8')
                except Exception:
                    # fallback below
                    pass

            # 2) optionally, try to interpret the bytes as ASN.1 using the compiled spec
            if asn_try_nested and spec is not None:
                tname, decoded = self.try_asn1_decode_bytes(spec, b, types_to_try=nested_types)
                # Skip nested decoding for "Payload" type - keep as hex (but try smart decode)
                if tname and tname != "Payload":
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
        if isinstance(obj, (list, tuple)):
            # For lists, keep same context path since list items are typically same type
            return [self.make_json_safe(v, spec=spec, asn_try_nested=asn_try_nested, nested_types=nested_types, context_path=context_path) for v in obj]

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

    def try_decode_file(self, spec, candidate_roots, data):
        """
        Try each root type until one succeeds. Returns (root_used, decoded) or (None, exception).
        """
        last_exc = None
        for root in candidate_roots:
            try:
                decoded = spec.decode(root, data)
                return root, decoded
            except Exception as e:
                last_exc = e
        return None, last_exc

    # Process a single file
    # Returns (status, result)
    def process(self, input_file, roots='', encoding='der') -> Tuple[bool, Any]:
        candidate_roots = [r.strip() for r in roots.split(',') if r.strip()]
        if not candidate_roots:
            candidate_roots = ['IRIsContent', 'IRIRecord', 'IRI-Begin', 'IRI-Continue', 'IRI-End', 'IRI', 'PS-PDU']

        with open(input_file, 'rb') as f:
            data = f.read()

        root_used, result = self.try_decode_file(self.spec, candidate_roots, data)
        
        if root_used:
            json_safe = self.make_json_safe(result, spec=self.spec)
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

    def process_dir(self, input_dir, output_dir, roots='', encoding='der', save_raw_on_fail=True, asn_try_nested=True, nested_types=None):
        os.makedirs(output_dir, exist_ok=True)

        candidate_roots = [r.strip() for r in roots.split(',') if r.strip()]
        if not candidate_roots:
            candidate_roots = ['IRIsContent', 'IRIRecord', 'IRI-Begin', 'IRI-Continue', 'IRI-End', 'IRI', 'PS-PDU']

        print(f"[+] Candidate root types: {candidate_roots}")
        print(f"[+] Nested ASN.1 probing of bytes is {'ENABLED' if asn_try_nested else 'DISABLED'}")

        # If user provided nested_types, respect them (split comma)
        nested_types_list = None
        if nested_types:
            nested_types_list = [t.strip() for t in nested_types.split(',') if t.strip()]

        for entry in sorted(os.listdir(input_dir)):
            fullpath = os.path.join(input_dir, entry)
            if not os.path.isfile(fullpath):
                continue

            with open(fullpath, 'rb') as f:
                data = f.read()

            print(f"[ ] Decoding: {entry} ({len(data)} bytes)")
            root_used, result = self.try_decode_file(self.spec, candidate_roots, data)

            base_name = os.path.splitext(entry)[0]
            if root_used:
                json_safe = self.make_json_safe(result, spec=self.spec, asn_try_nested=asn_try_nested, nested_types=nested_types_list)
                out_json_path = os.path.join(output_dir, base_name + ".json")
                with open(out_json_path, 'wb') as outf:
                    outf.write(orjson.dumps({
                        "decoded_with_root": root_used,
                        "content": json_safe
                    }, option=orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_DATACLASS | orjson.OPT_SERIALIZE_NUMPY))

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch decode ASN.1 DER/BER files to JSON. Nested ASN.1 decoding of bytes is optional.")
    parser.add_argument("--asn", required=True, help="Directory containing ASN.1 files")
    parser.add_argument("--input", required=True, help="Directory with binary files to decode")
    parser.add_argument("--output", required=True, help="Directory to write decoded JSON and error files")
    parser.add_argument("--roots", default="", help="Comma-separated candidate root ASN.1 types (e.g. 'IRIsContent,IRIRecord')")
    parser.add_argument("--encoding", default="der", choices=["der", "ber"], help="Encoding used when compiling the ASN.1 files")
    parser.add_argument("--no-save-raw-on-fail", dest="save_raw", action="store_false", help="Don't save raw .bin/.hex when decode fails")
    parser.add_argument("--no-nested-asn", dest="asn_try_nested", action="store_false", help="Don't attempt nested ASN.1 decoding of bytes")
    parser.add_argument("--nested-types", default="", help="If provided, comma-separated type names to try when probing bytes (limits probing scope)")
    args = parser.parse_args()

    decoder = ASN1Decoder(args.asn)

    decoder.process_dir(args.input, args.output, args.roots, encoding=args.encoding,
                save_raw_on_fail=args.save_raw, asn_try_nested=args.asn_try_nested, nested_types=args.nested_types)
