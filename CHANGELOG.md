# Changelog

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
