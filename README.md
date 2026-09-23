# ETSI ASN1 Decoder

Smart ASN.1 DER Decoder for ETSI Specs

## SMS decoding

SMS content fields are decoded as **bare TPDUs**. Strip any modem SMSC prefix
or RP envelope before calling the SMS API. The parser supports SMS-DELIVER,
SMS-SUBMIT, SMS-STATUS-REPORT, SMS-COMMAND, SMS-DELIVER-REPORT and
SMS-SUBMIT-REPORT, including ACK/error variants and optional report fields.

```python
from etsi_asn1_decoder.sms import decode_tpdu, reassemble_sms

tpdu = bytes.fromhex("0005912143f500006290422143654005e8329bfd06")
sms = decode_tpdu(tpdu, direction="sc-to-ms")
assert sms["message"] == "hello"
assert sms["originating_address"] == "+12345"
```

The existing `ASN1Decoder.decode_sms_pdu()` method accepts the same optional
`direction` and `report_kind` arguments. Direction is `"sc-to-ms"` (service
centre to mobile) or `"ms-to-sc"` (mobile to service centre). For a report,
pass `report_kind="ack"` or `"error"` from the enclosing RP message when known.
Message-type bits alone do not distinguish every TPDU type.

If context is omitted, automatic detection first tries the usual layout for the
message-type bits: DELIVER, SUBMIT, or STATUS-REPORT. A successful complete parse
is returned immediately so permissive report parsing cannot hide valid text.
Only if that fails does it try the opposite direction (reports or COMMAND).
Explicit direction/report hints override this preference. Inferred context is
marked with `direction_inferred` / `report_kind_inferred` as applicable.
If the fallback cannot distinguish ACK from error, it returns
`type="SMS-AMBIGUOUS"`, candidate types, and the original hex.
Invalid or truncated TPDUs
return `None`; ASN.1 SMS content remains `hex:...` rather than falling through
to phone-number, identifier, printable-text, or nested ASN.1 heuristics.

Decoded results include:

- Numeric and GSM-7 alphanumeric addresses, with type-of-number and numbering
  plan metadata. International numeric addresses now include `+`.
- GSM-7 text including extension characters, UCS-2/UTF-16BE text, and group-aware
  DCS metadata for message class, automatic deletion, and message waiting.
- Raw binary payloads for 8-bit data, without a Latin-1 text interpretation.
- Parsed UDH elements, 8/16-bit concatenation references, segment numbers,
  8/16-bit application ports, and message-waiting/shift-table identifiers.
  Unknown elements are retained as hex. Repeated non-repeatable elements use
  their last occurrence.
- Protocol ID, flags, timestamps, and the relevant validity-period, status,
  command, or failure fields. Timestamps retain their two-digit year and signed
  timezone offset; no century is guessed.

`raw_hex` always preserves the complete TPDU. `user_data_raw_hex` includes the
UDH; `user_data_hex` excludes it. For packed GSM-7, that byte slice may include
fill bits, so use `user_data_septets_hex` for the unpacked text septets.
`message` is emitted only after successful text decoding, including valid empty
text. Malformed text has a `text_decoding_error` and its raw payload.

Compressed SMS text (TS 23.042) and non-default national language shift tables
are identified and preserved with a `text_decoding_error`; they are not decoded
using the wrong alphabet. Reserved DCS codings use the GSM-7 fallback specified
by TS 23.038 and are marked `reserved`. Enhanced validity-period extensions that
are not understood are retained and marked `unsupported`.

## Multipart SMS

Decode each TPDU, then call `reassemble_sms(parts)` (also available on
`ASN1Decoder`) with segments known to belong to **one conversation and message**:

```python
parts = [decode_tpdu(pdu, direction="sc-to-ms") for pdu in segment_pdus]
combined = reassemble_sms(parts)
if combined["complete"]:
    text = combined.get("message")  # Binary/undecodable content has no message.
else:
    missing = combined["missing_segments"]
```

Assembly accepts out-of-order segments and identical retransmissions, checks
addresses, protocol/DCS, reference width/value, total count, and ports, and
rejects conflicts with `ValueError`. Missing segments never produce a partial
`message`. Packed GSM-7 is decoded per segment before joining; binary payloads
are concatenated as bytes. The output retains the original segment hex.

Grouping is explicit because an SMS-DELIVER TPDU does not contain its recipient
and concatenation references are reused. There is no global cache that could
mix subscribers, captures, or separate messages with the same reference.

## Tests

After installing `requirements.txt`, run:

```console
python -m unittest discover -s tests -v
```

The tests cover wire vectors, all six TPDU types, character encodings, UDH
alignment, multipart conflicts/missing segments, malformed inputs, and the
ASN.1-to-JSON integration.

Protocol references: [3GPP TS 23.040](https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/11.05.00_60/ts_123040v110500p.pdf)
and [3GPP TS 23.038](https://www.etsi.org/deliver/etsi_ts/123000_123099/123038/16.00.00_60/ts_123038v160000p.pdf).
