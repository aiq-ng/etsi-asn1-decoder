# ETSI ASN1 Decoder

ASN.1 BER/DER decoder with explicit ETSI field formats, CS/DSS1/ISUP parameters,
EPS/GTPv2/NAS values, location formats, and SMS TPDU support.

See [field coverage](docs/field-coverage.md) for supported wire layouts, remaining
gaps, and an audit command for your own ASN.1 schemas. Mapping a field does not
mean that every protocol extension inside it can be interpreted.

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

The identity portion of the registry follows **ETSI TS 101 671 V3.14.1, annex D**:

| Exact parent/field or CHOICE path | Built-in format |
| --- | --- |
| `lawfulInterceptionIdentifier` | `ascii-text` |
| `communication-Identity-Number` | `ascii-digits` |
| `operator-Identifier` | `ascii-text` |
| `globalCellID` | `map-global-cell-id` |
| `network-Element-Identifier.e164-Format`, `servingSystem.e164-Format` | `isup-calling` |
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
`imsi`, an unrelated `other.imsi`, or an unrelated `other.dSS1-Format` remains hex.
This registry implements known definitions; it does not infer semantics from
arbitrary ASN.1 files. The registry is not exhaustive across ETSI profiles.

`globalCellID` produces `MCC`, `MNC`, `LAC`, and (when present) `CellID`, plus
the complete `raw_hex`. MCC/MNC remain digit strings with leading zeroes;
LAC/CellID remain decimal strings for compatibility with the existing helper.
The MAP format supports five octets (MCC/MNC/LAC) and seven octets (also CI).
Six-octet values have an incomplete two-octet CI and remain hex, as do invalid
digits, misplaced filler and other unsupported lengths. No partial CI is invented.
This format does not apply to LTE/NR CGI, routing-area or service-area fields.

The location layout follows [TS 29.002, MAP-CommonDataTypes GlobalCellId](https://www.etsi.org/deliver/etsi_ts/129000_129099/129002/17.02.00_60/ts_129002v170200p.pdf).
Network element E.164 choices use the ISUP calling-party format specified in
TS 101 671, including both header octets and odd-digit filler handling.
`operator-Identifier` uses the exact field name under any enclosing record;
unsupported text bytes retain hex. These mappings are independent of operator
names and record variants, and use the same profile override rules as other fields.

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
| `map-global-cell-id` | MAP MCC/MNC + two-octet LAC, optionally a complete two-octet CI; five or seven octets |
| `isup-called`, `isup-calling` | Q.763 parameter contents, two header octets then decimal digits; excludes parameter tag/length |
| `ascii-digits`, `utf-8` | Explicit text encoding |
| `ascii-text` | Nonempty ASCII bytes in `0x20` through `0x7e`, preserved exactly; no trimming or replacement |
| `ipv4`, `ipv6`, `uuid`, `uint-be` | Explicit binary representation (`uint-be`: unsigned, 1–8 octets) |
| `hex` | Preserve original bytes |
| `ip-address` | Four- or sixteen-octet binary IP address; checks declared `iP-type` when available |
| `gtpv2-apn` | APN DNS labels or dotted ASCII, with the detected encoding named |
| `apn-dns-labels`, `apn-text` | Require one specific APN encoding |
| `gtpv2-ambr` | Eight-octet APN-AMBR; unsigned uplink/downlink rates in kbps |
| `gtpv2-ebi`, `gtpv2-rat` | EPS bearer ID or known RAT code |
| `gtpv2-bearer-qos` | ARP, QCI, and four unsigned 40-bit rates in kbps |
| `gtpv2-paa` | PDN type and IPv4/IPv6 address allocation |
| `gtpv2-uli` | CGI, SAI, RAI, TAI, ECGI, LAI, macro-eNodeB and extended macro-eNodeB |
| `pco-ue-to-network`, `pco-network-to-ue` | PCO framing and supported direction-specific contents |

Additional CS, location, NAS and traffic-filter formats are listed in the
[coverage reference](docs/field-coverage.md). The complete accepted format set
is available as `etsi_asn1_decoder.decoder.SUPPORTED_FIELD_FORMATS`.

E.164 is a numbering plan, not a unique wire encoding. MAP AddressString and
ISUP party-number contents must not share a decoder. The TBCD identity formats
above do not accept NAS mobile-identity headers. Unsupported encodings and
non-decimal dialling symbols should remain hex until a suitable format decoder
is provided. Only the documented parent/field combinations have defaults;
unrecognized profiles can add explicit overrides.

Generic nested ASN.1 probing is also restricted to CC payload contexts or
explicit `nested_types`, so identity bytes cannot accidentally match an unrelated
ASN.1 type. Configured field formats take precedence over that probing.

## EPS and GTPv2 fields

The following exact trailing paths also decode automatically. GTPv2 byte formats
expect IE **values**, excluding the type, length, and instance header. PCO begins
at its configuration-protocol octet (octet 3 in TS 24.008).

| Exact parent/field or CHOICE path | Built-in format |
| --- | --- |
| `ePSCorrelationNumber` | `utf-8` |
| `iP-value.iPBinaryAddress` | `ip-address` |
| `ePS-GTPV2-specificParameters.aPN` | `gtpv2-apn` |
| `ePS-GTPV2-specificParameters.aPN-AMBR` | `gtpv2-ambr` |
| `ePS-GTPV2-specificParameters.ePSBearerIdentity`, `ePS-GTPV2-specificParameters.linkedEPSBearerId` | `gtpv2-ebi` |
| `ePS-GTPV2-specificParameters.rATType` | `gtpv2-rat` |
| `ePS-GTPV2-specificParameters.ePSBearerQoS` | `gtpv2-bearer-qos` |
| `ePS-GTPV2-specificParameters.pDNAddressAllocation` | `gtpv2-paa` |
| `ePSlocationOfTheTarget.userLocationInfo`, `ePSlocationOfTheTarget.olduserLocationInfo` | `gtpv2-uli` |
| `protConfigOptions.ueToNetwork` | `pco-ue-to-network` |
| `protConfigOptions.networkToUe` | `pco-network-to-ue` |

`ePSCorrelationNumber` uses strict UTF-8 when valid and otherwise stays hex.
For example, ASCII bytes for `session-1` become `"session-1"`, whereas
`7974863829dc4381` remains `"hex:7974863829dc4381"`. Valid UTF-8 is preserved
exactly, including empty strings and control characters; there is no trimming,
replacement, or numeric conversion. This is a presentation policy for an opaque
identifier, not a guarantee that a sender uses text. Select `hex` explicitly if
your consumer requires stable hexadecimal keys for every correlation value.

Compound results retain the complete `raw_hex`. APNs return `name` and `encoding`:
standard length-prefixed labels produce `dns-labels`, while compatible dotted
ASCII values produce `dotted-ascii`. Use an explicit `apn-dns-labels` or `apn-text`
override to require a single encoding. Unrelated fields do not gain generic text
guessing. Malformed or unsupported values retain hex without partial consumption.

Bearer QoS returns QCI, priority, raw numeric pre-emption bits, and maximum and
guaranteed uplink/downlink rates. APN-AMBR and QoS rates are in **kbps**. ULI returns
each flagged location independently; MCC/MNC and numeric location codes are strings.
Macro-eNodeB and extended macro-eNodeB variants include the declared ID width.
PAA supports IPv4, IPv6, dual stack, Non-IP, and Ethernet; the IPv6 form requires
the specified /64 prefix length. Unknown RAT codes stay hex.

PCO retains entry order, duplicate IDs, lengths, and raw contents. Supported
interpretations include PAP, IPCP address/DNS/NBNS options, P-CSCF/DNS address
containers, IPv4 MTU, and bearer control. Request and response meanings depend
on the configured direction. PAP credential/message bytes remain raw; unsupported
protocols and containers carry `unsupported: true` with their bytes intact.
Malformed supported contents carry `decode_error` without erasing later entries.
Malformed outer framing leaves the entire PCO value as hex. This is not a decoder
for every protocol that PCO can carry.

Wire references: [TS 29.274 V17.10.0, clauses 8.6-8.21](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/17.10.00_60/ts_129274v171000p.pdf),
[TS 24.008 V17.9.0, clause 10.5.6.3](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/17.09.00_60/ts_124008v170900p.pdf),
[RFC 1334](https://www.rfc-editor.org/rfc/rfc1334.html),
[RFC 1332](https://www.rfc-editor.org/rfc/rfc1332.html), and
[RFC 1877](https://www.rfc-editor.org/rfc/rfc1877.html).

## CS, location and schema coverage

CS `services-Information` and `standard-Supplementary-Services` mappings now
dispatch ISUP parameter TLVs and DSS1 information elements. For example:

- `020103`: transmission medium requirement, **3.1 kHz audio**.
- `34029181`: teleservice information, **telephony**.
- `04038090a3`: bearer capability, **speech, 64 kbps, G.711 A-law**.

Results retain parameter identifiers, lengths and complete `raw_hex`. Unknown
parameters or codesets carry `unsupported: true`; malformed known inner values
carry `decode_error`. Invalid outer framing stays hex. Neither case tries an
unrelated ASN.1 root. This is parameter decoding, not a complete ISUP/MAP stack.

Location support includes PLMN/LAI/RAI/SAI/TAI/ECGI, classic GAD shapes, CSG IDs,
and EPS TAI lists. CS SGs `tAI`/`eCGI` retain their length octet; bare EPS values
use separate formats. Explicit `ncgi` and `5gs-tai` formats accept their distinct
layouts without claiming complete 5G HI2 support.

Audit a schema without needing intercepted data:

```sh
etsi-asn1-coverage schemas/Example.asn --root Example:Record > coverage.json
# Equivalent module invocation:
python -m etsi_asn1_decoder.coverage schemas/Example.asn --root Example:Record
```

Use `--root` repeatedly for multiple module-qualified roots. The report follows
imports, aliases, choices and list members, distinguishing mapped byte fields,
opaque fields, unresolved types, recursion and traversal limits. Lists use a
representative `[0]` index; per-index overrides may differ in real records.
`--field-formats` and `--no-builtin-formats` mirror the decoder's profile options.
The API `audit_schema(asn1tools.parse_files(paths), [(module, root)])` also accepts
caller-normalized parse trees. Remote-operation macros unsupported by asn1tools
must be normalized by the caller; the audit never rewrites source schemas.

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
Version 0.3.0 adds structured EPS/GTPv2 values and UTF-8 correlation presentation.
Version 0.2.1 restored location and network field mappings. Version 0.2.0 added
strict PDU consumption and corrected byte-field and codec handling. Review the
migration notes and changed output shapes before updating a consumer.

Build and validate a release independently of any application:

```console
python -m pip install build
python -m build
python -m pip install --force-reinstall dist/etsi_asn1_decoder-0.3.0-py3-none-any.whl
python -m unittest discover -s tests -v
```

Run the installed-wheel tests from outside the source checkout as CI does, so
imports cannot silently pick up source files. After review, commit and publish
the release through your normal repository/package process. Consumers should pin
the published version, an immutable Git commit, or the validated wheel. A Git URL
without `@<commit>` follows a moving branch and is not a version pin. Upgrade and
restart the consuming Python process after installing; an already imported module
does not change in a running service. CI validates builds without publishing them.

Version 0.3.0 changes supported EPS fields from hex strings to structured values.
It also changes valid UTF-8 `ePSCorrelationNumber` values from hex to exact text;
invalid UTF-8 remains hex. Consumers of 0.2.x must review correlation keys and
saved output expectations. For an opaque-only profile, use an exact override such
as `{"iRI-Report-record.ePSCorrelationNumber": "hex"}` (supply each actual CHOICE
path you use), or disable built-ins. Unknown byte fields continue to stay hex.

Protocol references: [3GPP TS 23.040](https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/11.05.00_60/ts_123040v110500p.pdf)
and [3GPP TS 23.038](https://www.etsi.org/deliver/etsi_ts/123000_123099/123038/16.00.00_60/ts_123038v160000p.pdf).
