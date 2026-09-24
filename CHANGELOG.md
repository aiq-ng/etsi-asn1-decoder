# Changelog

## 0.4.0

- Expand exact ETSI mappings for CS service parameters, supplementary-service
  parameters, DSS1 numbers, release causes, call durations, location numbers,
  subnet masks, URI/header text, NAS fields, and selected mobility addresses.
- Add bounded ISUP/DSS1 parameter parsers, including bearer and teleservice
  information, causes, numbers, notifications and access-transport IE sequences.
  Preserve unsupported codesets, parameters, extensions and diagnostic bytes.
- Add PLMN/area identities, SGs length-prefixed TAI/ECGI, EPS TAI partial lists,
  CSG identities, seven classic GAD shapes, and ULI macro-eNodeB variants.
- Add NAS/ESM/GTP cause codes, attach/request/PDN types, PDP types, and traffic
  flow templates with IPv4, IPv6, port, SPI, traffic-class, flow-label and Ethernet
  components. Detach direction ambiguity is reported rather than guessed.
- Add `etsi-asn1-coverage` and a reusable schema audit API to report reachable
  byte fields, mappings and unresolved/opaque definitions without capture data.
- Add BER/DER integration, malformed-input, protocol-boundary, profile override,
  source-byte preservation and randomized regression tests.

### Migration

Additional fields now return dictionaries instead of hex strings, with complete
`raw_hex`. Consumers must accept these structured shapes or choose exact `hex`
overrides / disable built-ins. No routing or Kafka policy is imposed by this
library. Consumer adapters that force all service bytes to raw must delegate
registered formats to the library to expose the new decoding.

See `docs/field-coverage.md` for limits. A mapped field is not proof of complete
protocol support. MAP operations, vendor payloads, high-accuracy GAD extensions
and several PMIP/DSMIP values remain opaque. Schema coverage counts are static
path counts, not decoding success rates or certification against every release.

## 0.3.0

- Decode EPS/GTPv2 APN, APN-AMBR, bearer IDs, known RAT codes, bearer QoS,
  PAA, and the six base ULI location variants through exact field mappings.
  Retain complete raw bytes in structured results; unsupported values stay hex.
- Decode binary IPAddress choices and check the declared IPv4/IPv6 family.
- Parse PCO entries in order, including duplicates and direction-specific lengths.
  Interpret PAP, IPCP address options, P-CSCF/DNS containers, IPv4 MTU, and bearer
  control; preserve unsupported contents and report malformed inner packets.
- Present `ePSCorrelationNumber` as strict UTF-8 when valid, with lossless hex
  fallback for invalid UTF-8. Exact `hex` overrides and disabled built-ins remain
  authoritative. No replacement decoding, trimming, or numeric coercion occurs.
- Add synthetic BER/DER integration, IPv4/IPv6, direction, boundary, truncation,
  profile override, UTF-8, and randomized byte-preservation regressions.

### Migration

Supported EPS fields now return structured dictionaries instead of hex strings.
APNs include their detected encoding; rate fields use kbps. Correlation values
such as `session-1` become text, while invalid UTF-8 such as `7974863829dc4381`
remains hex. Review consumer output schemas and correlation keys when upgrading
from 0.2.x. Use exact field overrides or disable built-ins for binary-only profiles.
ULI macro-eNodeB extensions and unsupported PCO contents remain raw; this release
does not claim complete interpretation of all EPS or proprietary payloads.

## 0.2.1

- Connect the exact `globalCellID` field to the MAP location decoder and add
  the explicit `map-global-cell-id` profile format. Decode five-octet area
  identities and seven-octet cell identities, retaining the full `raw_hex`.
- Correct three-digit MNC ordering and reject nondecimal MCC/MNC digits or
  misplaced filler. Unsupported lengths stay hex, including six-octet values
  with an incomplete CI; no trailing octets are silently dropped.
- Decode `operator-Identifier` as printable ASCII and
  `network-Element-Identifier.e164-Format` as ISUP calling-party contents.
  The equivalent `servingSystem.e164-Format` path is also covered. Exact
  profile overrides and disabled built-ins continue to take precedence.
- Add BER/DER integration and malformed-input regressions for location and
  network identifiers, including two/three-digit MNCs and zero-prefixed codes.

## 0.2.0

- Restore readable LIIDs and decimal CINs through exact ETSI field mappings.
  Preserve leading zeroes and use hex for unsupported byte encodings.
- Add strict `ascii-text` and `use_builtin_formats=False` / `--no-builtin-formats`.
  Exact profile overrides remain authoritative, including `hex`.
- Reject invalid field mappings consistently before compiling schemas.
- Honor BER/DER selection in the constructor, public processing APIs and CLI.
  Preserve existing subclass compiler defaults when no codec is requested.
- Require complete consumption for root and nested PDU decoding. Reject unknown
  CHOICE alternatives that asn1tools represents as `(None, None)`.
- Restrict nested probes to the requested candidates or CC types. Prevent
  recursive probing of ANY values that return the same bytes.
- Share decoding behavior across file, bytes and directory APIs. Add synthetic
  regression tests and installed-wheel CI on Python 3.10/3.12/3.14, Linux/Windows.

### Migration

The base decoder now rejects concatenated PDUs or trailing data instead of silently
returning only the first PDU. Frame streams externally; a single ASN.1 SEQUENCE OF
remains supported. Unknown CHOICE alternatives require an appropriate schema.

LIID OCTET STRING values containing printable ASCII now become strings; decimal
CINs also become strings, preserving zeroes. Non-ASCII/empty/control-containing
LIIDs and nondecimal CINs remain hex. Native ASN.1 strings/integers are unchanged.
Profiles with binary identifiers should explicitly select `hex` or disable the
built-in registry; other encodings can use exact-path overrides. No application
topic naming, operator-specific values, or numeric coercion is performed.

Opaque fields outside the registry remain hex. This release does not restore
generic printable-byte or phone-number guessing, and does not claim to interpret
every proprietary payload or preserve unknown ASN.1 sequence extensions.
For example, `ePSCorrelationNumber` stays hex by default, as in the existing
field-registry implementation. Consumers upgrading from older heuristic decoders
must review correlation keys; profiles that require text can opt in explicitly.
