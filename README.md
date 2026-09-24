# ETSI ASN1 Decoder

ASN.1 BER/DER decoder with explicit ETSI field formats and SMS TPDU support.

## Decode contract

```python
from etsi_asn1_decoder.decoder import ASN1Decoder

decoder = ASN1Decoder("schemas", encoding="ber")
success, result = decoder.process("record.ber", roots="IRIContent,PS-PDU")
```

Choose the codec at construction, or pass `encoding="ber"` / `"der"` to
`process_bytes`, `process`, or `process_dir`. Per-call codec selection uses a
cached compiled schema and does not change the constructor's default. Omitting
the codec preserves the compiler's default (DER for the base class, or a
subclass's override). The CLI's `--encoding` option selects the actual compiler.

Each base-class input is **one complete PDU**. A root candidate must consume all
input bytes; trailing data, concatenated PDUs, truncation, and unsupported CHOICE
alternatives cannot produce a successful partial result. For a multi-PDU stream,
frame its records first and call `process_bytes` on each frame. `SEQUENCE OF`
records inside a single PDU are decoded together. Nested decoding also requires
full byte consumption and uses only the explicit `nested_types` or known CC type
candidates; failed CC probes do not search unrelated IRI types.

Success means the supplied schema decoded the complete PDU. It does not mean
every opaque OCTET STRING has a known protocol interpretation, nor does it prove
the supplied schema matches the sender's protocol revision. Unknown extensions
in extensible ASN.1 sequences may be skipped by asn1tools: retain source bytes
when exact wire preservation is required. Keep unsupported byte fields as hex
and supply a field profile where the encoding is known.

## Field-specific byte formats

Known ETSI phone and identity fields decode automatically using the built-in
field/format registry. No manual configuration is needed for these fields.
There are no byte-length, substring, or generic phone-number guesses.
Unmapped OCTET STRING values remain `hex:...`, even when
their bytes happen to be printable ASCII. ASN.1 string values remain strings.
An invalid value for the selected format stays hex; another decoder is never
tried. SMS content retains its dedicated TPDU decoding described below.

The initial registry follows **ETSI TS 101 671 V3.14.1, annex D**, covering:

| Exact parent/field or CHOICE path | Built-in format |
| --- | --- |
| `lawfulInterceptionIdentifier` | `ascii-text` |
| `communication-Identity-Number` | `ascii-digits` |
| `partyIdentity.imsi` | `imsi-tbcd` |
| `partyIdentity.imei` | `imei-tbcd` |
| `partyIdentity.msISDN` | `map-address` |
| `partyIdentity.e164-Format` | `isup-calling` |
| `partyIdentity.sip-uri`, `partyIdentity.tel-url` | `utf-8` |
| `callingPartyNumber.iSUP-Format` | `isup-calling` |
| `calledPartyNumber.iSUP-Format` | `isup-called` |
| `callingPartyNumber.mAP-Format`, `calledPartyNumber.mAP-Format` | `map-address` |

Built-ins match these complete, case-sensitive trailing path components under
any enclosing record. List indices do not affect built-in matching. A bare
`imsi`, an unrelated `other.imsi`, or an unsupported `dSS1-Format` remains hex.
This registry implements known definitions; it does not infer semantics from
arbitrary ASN.1 files. The initial registry is not exhaustive across ETSI profiles.

LIID and CIN use their exact, case-sensitive ETSI field names, including in
standalone roots, CHOICE alternatives, and lists. ASCII LIIDs (numeric or textual,
such as `TEST`) and decimal CINs retain leading zeroes. The LIID default preserves
all printable ASCII, including spaces and punctuation; it does not trim, sanitize,
apply application routing rules, or enforce a recommended alphabet. Empty,
non-ASCII, and control-containing octets remain hex. CIN defaults to ASCII digits,
as specified in TS 101 671 V3.14.1; earlier or vendor free-format CIN profiles can
override it with `ascii-text`, `utf-8`, `uint-be`, or `hex` as appropriate.

These are field-name defaults, not ASN.1 type inference. For another schema that
reuses these names with different semantics, set `use_builtin_formats=False`
(`--no-builtin-formats` in the CLI) and provide explicit field mappings. Overrides
still apply with built-ins disabled. Dedicated SMS decoding is a separate feature.

Reference: [ETSI TS 101 671, annex D, PartyInformation and party-number choices](https://www.etsi.org/deliver/etsi_ts/101600_101699/101671/03.14.01_60/ts_101671v031401p.pdf).

For custom fields or profiles, optionally supply exact full-path overrides:

```python
decoder = ASN1Decoder(asn_dir, field_formats={
    "identity.imsi": "imsi-tbcd",
    "party.msisdn": "map-address",
    "party.calledPartyNumber": "isup-called",
    "equipment.imei": "imei-tbcd",
    "label": "utf-8",
})
```

These override paths are examples. Overrides take precedence over built-ins;
use `"hex"` to disable decoding for a particular field. Paths are case-sensitive,
start at the decoded root's fields, and must match completely. CHOICE alternative
names are included (e.g. `identity.imsi`); list indices are included as `[0]`,
`[1]`, etc. The CHOICE JSON representation remains `[name, value]`.

For the CLI, put the same mapping in a JSON object and pass
`--field-formats field-formats.json`.

Supported formats:

| Format | Interpretation |
| --- | --- |
| `imsi-tbcd` | MAP IMSI decimal TBCD; preserves every identity digit |
| `imei-tbcd` | 15-digit IMEI in decimal TBCD |
| `tbcd-digits` | Decimal TBCD, final high-nibble `F` filler only |
| `map-address` | MAP AddressString, one TON/NPI octet then decimal TBCD |
| `isup-called`, `isup-calling` | Q.763 parameter contents, two header octets then decimal digits; excludes parameter tag/length |
| `ascii-digits`, `utf-8` | Explicit text encoding |
| `ascii-text` | Nonempty ASCII bytes in `0x20` through `0x7e`, preserved exactly; no trimming or replacement |
| `ipv4`, `ipv6`, `uuid`, `uint-be` | Explicit binary representation (`uint-be`: unsigned, 1–8 octets) |
| `hex` | Preserve original bytes |

E.164 is a numbering plan, not a unique wire encoding. MAP AddressString and
ISUP party-number contents must not share a decoder. The TBCD identity formats
above do not accept NAS mobile-identity headers. Unsupported encodings and
non-decimal dialling symbols should remain hex until a suitable format decoder
is provided. Only the documented parent/field combinations have defaults;
unrecognized profiles can add explicit overrides.

Generic nested ASN.1 probing is also restricted to CC payload contexts or
explicit `nested_types`, so identity bytes cannot accidentally match an unrelated
ASN.1 type. Configured field formats take precedence over that probing.

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
ASN.1-to-JSON integration. Identifier tests use synthetic BER/DER records,
all 256 single-octet values, binary and text profiles, nested records and CHOICEs.
Shared API tests cover codec selection, complete PDU consumption, directory/file
decoding, CLI options and constrained nested probing. CI tests the installed wheel
on Linux and Windows with Python 3.10, 3.12 and 3.14.

## Independent releases and upgrades

The library has its own version, tests, and release history in `CHANGELOG.md`.
Version 0.2.0 adds strict PDU consumption and corrects byte-field and codec handling;
review the migration notes before updating a consumer.

Build and validate a release independently of any application:

```console
python -m pip install build
python -m build
python -m pip install --force-reinstall dist/etsi_asn1_decoder-0.2.0-py3-none-any.whl
python -m unittest discover -s tests -v
```

Run the installed-wheel tests from outside the source checkout as CI does, so
imports cannot silently pick up source files. After review, commit and publish
the release through your normal repository/package process. Consumers should pin
the published version, an immutable Git commit, or the validated wheel. A Git URL
without `@<commit>` follows a moving branch and is not a version pin. Upgrade and
restart the consuming Python process after installing; an already imported module
does not change in a running service. CI validates builds without publishing them.

When migrating from releases with generic printable-byte guessing, review opaque
fields as well as identifiers. For example, `ePSCorrelationNumber` has no built-in
text conversion: even printable octets remain `hex:...`. If your sender's profile
explicitly defines ASCII here, opt in with an exact override such as
`{"iRI-Report-record.ePSCorrelationNumber": "ascii-text"}` (supply each actual
CHOICE path you use). Do not treat arbitrary correlation bytes as universally
textual. Compare consumer keys and saved output expectations before deployment.

Protocol references: [3GPP TS 23.040](https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/11.05.00_60/ts_123040v110500p.pdf)
and [3GPP TS 23.038](https://www.etsi.org/deliver/etsi_ts/123000_123099/123038/16.00.00_60/ts_123038v160000p.pdf).
