"""SMS transfer-layer decoding (3GPP TS 23.040 and TS 23.038).

Inputs are bare TPDUs, not modem PDUs with an SMSC prefix or RP envelopes.
No capture-global state is kept: callers explicitly select multipart segments.
"""

from datetime import datetime


GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXTENSION = {
    0x0A: "\f", 0x14: "^", 0x28: "{", 0x29: "}", 0x2F: "\\",
    0x3C: "[", 0x3D: "~", 0x3E: "]", 0x40: "|", 0x65: "€",
}


class SMSDecodeError(ValueError):
    """The TPDU is structurally invalid or truncated."""


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def take(self, count):
        if count < 0 or count > self.remaining:
            raise SMSDecodeError("Truncated TPDU")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def byte(self):
        return self.take(1)[0]


def unpack_septets(data, length, start_septet=0):
    if length < 0 or start_septet < 0 or (start_septet + length) * 7 > len(data) * 8:
        raise SMSDecodeError("Truncated GSM-7 data")
    packed = int.from_bytes(data, "little")
    return bytes((packed >> (7 * (start_septet + i))) & 127 for i in range(length))


def _gsm_text(septets):
    chars = []
    escaped = False
    for code in septets:
        if escaped:
            if code not in GSM7_EXTENSION:
                raise SMSDecodeError("Undefined GSM-7 extension character")
            chars.append(GSM7_EXTENSION[code])
            escaped = False
        elif code == 27:
            escaped = True
        else:
            chars.append(GSM7_BASIC[code])
    if escaped:
        raise SMSDecodeError("Incomplete GSM-7 escape sequence")
    return "".join(chars)


def decode_gsm7(data, length, start_septet=0):
    return _gsm_text(unpack_septets(data, length, start_septet))


def _address(reader):
    length, toa = reader.byte(), reader.byte()
    if length > 20 or not toa & 0x80:
        raise SMSDecodeError("Invalid address length or type")
    raw = reader.take((length + 1) // 2)
    ton = (toa >> 4) & 7
    if ton == 5:
        septets = length * 4 // 7
        if (septets * 7 + 3) // 4 != length:
            raise SMSDecodeError("Invalid alphanumeric address length")
        value = decode_gsm7(raw, septets)
    else:
        digits = []
        alphabet = "0123456789*#abc"
        for i in range(length):
            nibble = (raw[i // 2] >> (4 * (i % 2))) & 15
            if nibble == 15:
                raise SMSDecodeError("Filler inside address")
            digits.append(alphabet[nibble])
        if length % 2 and raw[-1] >> 4 != 15:
            raise SMSDecodeError("Missing address filler")
        value = ("+" if ton == 1 and length else "") + "".join(digits)
    return value, {"type_of_address": toa, "type_of_number": ton,
                   "numbering_plan": toa & 15, "raw_hex": raw.hex()}


def _bcd(byte):
    low, high = byte & 15, byte >> 4
    if low > 9 or high > 9:
        raise SMSDecodeError("Invalid timestamp BCD")
    return low * 10 + high


def _timestamp(raw):
    year, month, day, hour, minute, second = [_bcd(b) for b in raw[:6]]
    offset = _bcd(raw[6] & 0xF7) * 15 * (-1 if raw[6] & 8 else 1)
    # The wire format has no century. Validate against a leap-compatible year
    # without silently inventing a century in the returned value.
    datetime(2000 + year, month, day, hour, minute, second)
    if abs(offset) >= 24 * 60:
        raise SMSDecodeError("Invalid timezone offset")
    return {"year_two_digits": year, "month": month, "day": day,
            "hour": hour, "minute": minute, "second": second,
            "timezone_offset_minutes": offset, "raw_hex": raw.hex()}


def decode_dcs(value):
    """Interpret coding groups before interpreting alphabet/class bits."""
    result = {"value": value, "compressed": False, "encoding": "gsm-7bit"}
    group = value >> 4
    if value < 0x80:
        result.update(group="automatic-deletion" if value & 0x40 else "general",
                      compressed=bool(value & 0x20))
        result["encoding"] = ("gsm-7bit", "8-bit", "ucs-2", "gsm-7bit")[(value >> 2) & 3]
        if value & 0x10:
            result["message_class"] = value & 3
        if value & 0x0C == 0x0C:
            result["reserved"] = True
    elif group in (0xC, 0xD, 0xE):
        result.update(group="message-waiting", encoding="ucs-2" if group == 0xE else "gsm-7bit")
        result["message_waiting"] = {
            "active": bool(value & 8), "discard": group == 0xC,
            "kind": ("voicemail", "fax", "email", "other")[value & 3],
        }
        if value & 4:
            result["reserved"] = True
            result["encoding"] = "gsm-7bit"
    elif group == 0xF and not value & 8:
        result.update(group="message-class", encoding="8-bit" if value & 4 else "gsm-7bit",
                      message_class=value & 3)
    else:
        result.update(group="reserved", reserved=True)
    return result


def _header(data):
    reader = _Reader(data)
    length = reader.byte()
    body = reader.take(length)
    elements = _Reader(body)
    result = {"length": length, "raw_hex": body.hex(), "elements": []}
    expected = {0: 3, 8: 4, 4: 2, 5: 4, 0x24: 1, 0x25: 1, 1: 2}
    while elements.remaining:
        iei, size = elements.byte(), elements.byte()
        value = elements.take(size)
        if iei in expected and size != expected[iei]:
            raise SMSDecodeError("Invalid user-data header element length")
        result["elements"].append({"id": iei, "length": size, "raw_hex": value.hex()})
        key, decoded = None, None
        if iei in (0, 8):
            key = "concatenation"
            decoded = {"reference": int.from_bytes(value[:-2], "big"),
                       "reference_bits": 8 if iei == 0 else 16,
                       "total": value[-2], "sequence": value[-1]}
            if not 1 <= decoded["sequence"] <= decoded["total"]:
                raise SMSDecodeError("Invalid concatenation sequence")
        elif iei in (4, 5):
            key = "ports"
            half = size // 2
            decoded = {"destination": int.from_bytes(value[:half], "big"),
                       "source": int.from_bytes(value[half:], "big"), "bits": half * 8}
        elif iei in (0x24, 0x25):
            key = "single_shift" if iei == 0x24 else "locking_shift"
            decoded = value[0]
        elif iei == 1:
            result.setdefault("message_waiting", []).append({
                "store": bool(value[0] & 0x80), "type": value[0] & 0x7F, "count": value[1]})
        if key:
            # TS 23.040 9.2.3.24: the last occurrence wins for duplicated
            # non-repeatable or mutually exclusive elements (e.g. port widths).
            result[key] = decoded
    return result, length + 1


def _set_text(result, payload, septets=None):
    """Retain undecodable content without manufacturing readable text."""
    if result["coding_scheme"]["compressed"]:
        result["text_decoding_error"] = "Compressed SMS text is not supported"
        return
    if result["encoding"] == "8-bit":
        return
    header = result.get("user_data_header", {})
    if result["encoding"] == "gsm-7bit" and (header.get("locking_shift", 0) or header.get("single_shift", 0)):
        result["text_decoding_error"] = "National language shift table is not supported"
        return
    try:
        result["message"] = _gsm_text(septets) if septets is not None else payload.decode("utf-16-be")
    except (ValueError, UnicodeError) as exc:
        result["text_decoding_error"] = str(exc)


def _user_data(reader, result, limit=140):
    udl = reader.byte()
    scheme = result["coding_scheme"]
    gsm = scheme["encoding"] == "gsm-7bit" and not scheme["compressed"]
    octets = (udl * 7 + 7) // 8 if gsm else udl
    if octets > limit:
        raise SMSDecodeError("User data exceeds TPDU limit")
    raw = reader.take(octets)
    result.update(user_data_length=udl, user_data_raw_hex=raw.hex())
    offset = 0
    if result["flags"]["udhi"]:
        result["user_data_header"], offset = _header(raw)
    payload = raw[offset:]
    result["user_data_hex"] = payload.hex()
    septets = None
    if gsm:
        skip = (offset * 8 + 6) // 7
        if skip > udl:
            raise SMSDecodeError("Header exceeds user data length")
        septets = unpack_septets(raw, udl - skip, skip)
        result["user_data_septets_hex"] = septets.hex()
    _set_text(result, payload, septets)


def _relative_validity(value):
    if value <= 143:
        return (value + 1) * 5 * 60
    if value <= 167:
        return 12 * 3600 + (value - 143) * 30 * 60
    if value <= 196:
        return (value - 166) * 86400
    return (value - 192) * 7 * 86400


def _validity(reader, form):
    if form == 2:
        value = reader.byte()
        return {"format": "relative", "raw_hex": f"{value:02x}", "seconds": _relative_validity(value)}
    raw = reader.take(7)
    if form == 3:
        return {"format": "absolute", **_timestamp(raw)}
    result = {"format": "enhanced", "raw_hex": raw.hex(), "single_shot": bool(raw[0] & 0x40)}
    kind = raw[0] & 7
    if raw[0] & 0xB8 or kind > 3:
        result["unsupported"] = True
    elif kind == 1:
        result["seconds"] = _relative_validity(raw[1])
    elif kind == 2:
        if raw[1] == 0:
            raise SMSDecodeError("Reserved enhanced validity period")
        result["seconds"] = raw[1]
    elif kind == 3:
        h, m, s = map(_bcd, raw[1:4])
        if h > 23 or m > 59 or s > 59:
            raise SMSDecodeError("Invalid enhanced validity period")
        result["seconds"] = h * 3600 + m * 60 + s
    return result


def _coding(reader, result):
    value = reader.byte()
    result.update(dcs=value, coding_scheme=decode_dcs(value))
    result["encoding"] = result["coding_scheme"]["encoding"]


def _parameters(reader, result, timestamp=False):
    pi = [reader.byte()]
    while pi[-1] & 0x80:
        pi.append(reader.byte())
    result["parameter_indicators"] = pi
    if timestamp:
        result["timestamp"] = _timestamp(reader.take(7))
    if pi[0] & 1:
        result["protocol_id"] = reader.byte()
    if pi[0] & 2:
        _coding(reader, result)
    if pi[0] & 4:
        if "dcs" not in result:
            result.update(dcs=0, dcs_defaulted=True, coding_scheme=decode_dcs(0), encoding="gsm-7bit")
        _user_data(reader, result, limit=164 - reader.pos - 1)
    elif result["flags"]["udhi"]:
        raise SMSDecodeError("UDHI without user data")
    # Reserved PI bits announce extensions after the known fields.
    if pi[0] & 0x78 or any(value & 0x7F for value in pi[1:]):
        result["parameter_extension_hex"] = reader.take(reader.remaining).hex()


_TYPES = {
    "sc-to-ms": ("SMS-DELIVER", "SMS-SUBMIT-REPORT", "SMS-STATUS-REPORT"),
    "ms-to-sc": ("SMS-DELIVER-REPORT", "SMS-SUBMIT", "SMS-COMMAND"),
}


def _parse(data, direction, report_kind):
    reader = _Reader(data)
    first = reader.byte()
    kind = _TYPES[direction][first & 3]
    result = {"type": kind, "direction": direction, "raw_hex": data.hex(),
              "first_octet": first, "flags": {"udhi": bool(first & 0x40)}}
    flags = result["flags"]
    if kind in ("SMS-DELIVER", "SMS-STATUS-REPORT"):
        flags.update(more_messages=not bool(first & 4), loop_prevention=bool(first & 8))
    if kind in ("SMS-DELIVER", "SMS-SUBMIT"):
        flags["reply_path"] = bool(first & 0x80)
    if kind == "SMS-DELIVER":
        flags["status_report_indication"] = bool(first & 0x20)
        result["originating_address"], result["originating_address_info"] = _address(reader)
        result["protocol_id"] = reader.byte()
        _coding(reader, result)
        result["timestamp"] = _timestamp(reader.take(7))
        _user_data(reader, result)
    elif kind == "SMS-SUBMIT":
        flags.update(reject_duplicates=bool(first & 4), status_report_request=bool(first & 0x20))
        result["message_reference"] = reader.byte()
        result["destination_address"], result["destination_address_info"] = _address(reader)
        result["protocol_id"] = reader.byte()
        _coding(reader, result)
        form = (first >> 3) & 3
        result["validity_period_format"] = form
        if form:
            result["validity_period"] = _validity(reader, form)
        _user_data(reader, result)
    elif kind == "SMS-STATUS-REPORT":
        flags["status_report_qualifier"] = bool(first & 0x20)
        result["message_reference"] = reader.byte()
        result["recipient_address"], result["recipient_address_info"] = _address(reader)
        result["timestamp"] = _timestamp(reader.take(7))
        result["discharge_time"] = _timestamp(reader.take(7))
        result["status"] = reader.byte()
        if reader.remaining:
            _parameters(reader, result)
        elif flags["udhi"]:
            raise SMSDecodeError("UDHI without user data")
    elif kind == "SMS-COMMAND":
        flags["status_report_request"] = bool(first & 0x20)
        for name in ("message_reference", "protocol_id", "command_type", "message_number"):
            result[name] = reader.byte()
        result["destination_address"], result["destination_address_info"] = _address(reader)
        length = reader.byte()
        if length > 156:
            raise SMSDecodeError("Command data exceeds limit")
        payload = reader.take(length)
        result.update(command_data_length=length, command_data_raw_hex=payload.hex())
        offset = 0
        if flags["udhi"]:
            result["user_data_header"], offset = _header(payload)
        result["command_data_hex"] = payload[offset:].hex()
    else:
        result["report_kind"] = report_kind
        if report_kind == "error":
            cause = reader.byte()
            if cause < 0x80:
                raise SMSDecodeError("Invalid failure cause")
            result["failure_cause"] = cause
            if first & 0xBC:
                result["effective_failure_cause"] = 0xFF
        _parameters(reader, result, timestamp=kind == "SMS-SUBMIT-REPORT")
    if reader.remaining:
        raise SMSDecodeError("Trailing bytes after TPDU")
    return result


def decode_tpdu(data, direction=None, report_kind=None):
    """Return a decoded TPDU, an ambiguity record, or None for invalid data.

    direction: 'ms-to-sc' or 'sc-to-ms'. report_kind: 'ack' or 'error'
    from the enclosing RP message. Without hints, try the usual MTI layout
    (DELIVER, SUBMIT, STATUS-REPORT) first. Only try the opposite direction
    if that complete parse fails; permissive report extensions must not mask
    a valid message. Explicit hints always take precedence.
    """
    if direction is not None and direction not in _TYPES:
        raise ValueError("direction must be 'ms-to-sc' or 'sc-to-ms'")
    if report_kind not in (None, "ack", "error"):
        raise ValueError("report_kind must be 'ack' or 'error'")
    if not data or len(data) > 164 or data[0] & 3 == 3:
        return None
    directions = [direction] if direction else list(_TYPES)
    if direction is None and report_kind is None:
        preferred = "ms-to-sc" if data[0] & 3 == 1 else "sc-to-ms"
        try:
            result = _parse(data, preferred, None)
        except ValueError:
            directions.remove(preferred)
        else:
            result["direction_inferred"] = True
            return result
    candidates = []
    for candidate_direction in directions:
        kind = _TYPES[candidate_direction][data[0] & 3]
        is_report = kind in ("SMS-DELIVER-REPORT", "SMS-SUBMIT-REPORT")
        if report_kind and not is_report:
            continue
        variants = ([report_kind] if report_kind else ["ack", "error"]) if is_report else [None]
        for variant in variants:
            try:
                candidates.append(_parse(data, candidate_direction, variant))
            except ValueError:
                continue
    if len(candidates) == 1:
        result = candidates[0]
        if direction is None:
            result["direction_inferred"] = True
        if report_kind is None and "report_kind" in result:
            result["report_kind_inferred"] = True
        return result
    if candidates:
        return {"type": "SMS-AMBIGUOUS", "raw_hex": data.hex(),
                "reason": "Supply direction and RP report_kind to disambiguate",
                "candidates": [{k: c[k] for k in ("type", "direction", "report_kind") if k in c}
                               for c in candidates]}
    return None


def reassemble_sms(parts):
    """Combine decoded segments from ONE caller-selected conversation/message.

    Missing segments are reported without a partial 'message'. Conflicting
    duplicates and mismatched metadata raise ValueError. No cache or timer
    guesses which subscriber owns a short, frequently reused reference.
    """
    parts = list(parts)
    if not parts:
        raise ValueError("No SMS segments supplied")
    by_sequence = {}
    identity = None
    for part in parts:
        header = part.get("user_data_header", {})
        concat = header.get("concatenation")
        if not concat or part.get("type") not in ("SMS-DELIVER", "SMS-SUBMIT"):
            raise ValueError("Expected concatenated SMS-DELIVER or SMS-SUBMIT segments")
        key = (part["type"], part.get("direction"), part.get("originating_address"),
               part.get("originating_address_info"), part.get("destination_address"),
               part.get("destination_address_info"), part.get("protocol_id"), part.get("dcs"),
               concat["reference"], concat["reference_bits"], concat["total"], header.get("ports"))
        if identity is not None and key != identity:
            raise ValueError("Segments do not belong to the same message")
        identity = key
        sequence = concat["sequence"]
        if not 1 <= sequence <= concat["total"] <= 255:
            raise ValueError("Invalid segment sequence")
        if sequence in by_sequence and by_sequence[sequence]["raw_hex"] != part["raw_hex"]:
            raise ValueError("Conflicting duplicate segment")
        by_sequence[sequence] = part
    first = parts[0]
    concat = first["user_data_header"]["concatenation"]
    missing = [i for i in range(1, concat["total"] + 1) if i not in by_sequence]
    result = {"type": "SMS-REASSEMBLED", "encoding": first["encoding"],
              "reference": concat["reference"], "reference_bits": concat["reference_bits"],
              "total": concat["total"], "received": len(by_sequence),
              "complete": not missing, "missing_segments": missing,
              "segments_raw_hex": [by_sequence[i]["raw_hex"] for i in sorted(by_sequence)]}
    for name in ("originating_address", "destination_address", "direction", "protocol_id", "dcs"):
        if name in first:
            result[name] = first[name]
    if "ports" in first["user_data_header"]:
        result["ports"] = first["user_data_header"]["ports"]
    if missing:
        return result
    ordered = [by_sequence[i] for i in range(1, concat["total"] + 1)]
    payload = b"".join(bytes.fromhex(p["user_data_hex"]) for p in ordered)
    if first["encoding"] == "gsm-7bit" and not first["coding_scheme"]["compressed"]:
        # Septet packing restarts in every segment; packed octets cannot simply
        # be concatenated. Shift tables also apply independently per segment.
        if all("message" in p for p in ordered):
            result["message"] = "".join(p["message"] for p in ordered)
        else:
            result["text_decoding_error"] = "One or more segments could not be decoded"
        result["user_data_septets_hex"] = "".join(p["user_data_septets_hex"] for p in ordered)
    else:
        result["user_data_hex"] = payload.hex()
        if first["coding_scheme"]["compressed"]:
            result["text_decoding_error"] = "Compressed SMS text is not supported"
        elif first["encoding"] == "ucs-2":
            if all("message" in p for p in ordered):
                result["message"] = "".join(p["message"] for p in ordered)
            else:
                result["text_decoding_error"] = "One or more segments could not be decoded"
    return result
