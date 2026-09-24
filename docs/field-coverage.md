# Field coverage and limits

The registry selects a byte decoder from complete, case-sensitive trailing path
components. It is not a claim that all ETSI ASN.1 modules use identical encodings.
Exact full-path overrides take precedence; `hex` and `use_builtin_formats=False`
remain available for profiles with different definitions.

Every compound protocol result retains the original `raw_hex`. Unknown outer
formats remain hex. Recognized framing with unknown contents preserves those
contents and reports `unsupported`; malformed known contents report
`decode_error`. Remaining bits and diagnostics are never passed to unrelated
ASN.1 roots. A recognized parameter name alone does not indicate full decoding.

## Support matrix

| Family | Implemented interpretation | Deliberate limits |
| --- | --- | --- |
| Identity and text | LIID/operator ASCII, decimal CIN, IMSI/IMEI TBCD, MAP addresses, ISUP calling/called/location numbers, DSS1 IA5 numbers, specified URI/header fields | No generic text/number guessing; decimal TBCD does not interpret special dialling symbols or NAS identity headers |
| Correlation | Strict UTF-8 for `ePSCorrelationNumber`, hex for invalid UTF-8 | Presentation policy for an opaque identifier; use `hex` for consistently binary keys |
| ISUP service TLVs | Tag/length framing, transmission requirements, party numbers, causes, user-service/bearer information, teleservices, notifications, nature/redirection/event/backward indicators, delay/hop counter, access transport | Other parameters retain bytes; national variants and detailed compatibility instructions are not interpreted |
| DSS1 IEs | Single-octet IEs/shifts, bearer capability, cause, HLC, notifications, numbers, display/keypad, call state/progress, subaddress/UUI headers | Codesets 4/5/6/7 are framed but opaque; facility/MAP invocation semantics, low-layer compatibility and bearer extension octets remain unsupported |
| Causes and durations | Q.850 standard cause/location, optional recommendation, raw diagnostics; BCD HHMMSS duration | National cause meanings and diagnostics remain raw; durations are BCD, not TBCD |
| Locations | MAP global cell ID; PLMN, LAI, RAI, SAI, TAI, ECGI; SGs TAI/ECGI; all three EPS TAI partial-list layouts; HI2 CSG ID | No coercion between bare values and length-prefixed IEs; five-octet MAP global cell IDs contain no cell identity |
| GAD coordinates | Point, uncertainty circle/ellipse, polygon, altitude, altitude uncertainty ellipsoid, arc | Classic quantization rules only; high-accuracy/scalable shapes remain hex; no invented confidence for unspecified codes |
| NR location formats | Explicit `ncgi` and `5gs-tai` overrides | Does not imply complete 5G HI2 schema support or automatically apply them to legacy names |
| EPS/GTPv2 | APN, AMBR, bearer IDs, RAT, bearer QoS, PAA; all eight ULI flag variants | IE values only; rates in kbps; unsupported/reserved variants remain raw; independent macro variants are mutually exclusive |
| NAS/GPRS | Attach/request/PDN type, PTI, NSAPI, PDP organization/type; EMM/ESM/GTP cause values | NAS and GTP enum assignments differ; detach reports direction ambiguity; no complete NAS message decoder |
| TFT/TAD | Outer operations/filter lengths, all component identifiers in TS 24.008 V17.9.0 table 10.5.162, ordered filters/parameters | Unknown components retain the remaining filter bytes; authorization-token and flow-identifier parameters remain raw; later filters remain available |
| PCO | Ordered entries and duplicates, PAP, IPCP, supported P-CSCF/DNS containers, MTU, bearer control | Direction must be known; unsupported protocols/containers remain raw, including LCP/CHAP; no credential text guessing |
| SMS | Supported TPDU variants, common text alphabets, UDH, multipart APIs | Not an RP envelope/SMSC-prefix decoder; compression and non-default shift tables remain explicitly unsupported |

## Wire formats available for explicit profiles

In addition to the identity/EPS formats in the README:

- CS: `isup-parameter`, `isup-location`, `q850-cause`, `bcd-duration`,
  `dss1-called`, `dss1-calling`, `dss1-bearer`, `dss1-high-layer`,
  `dss1-ie-0`, `dss1-ie-4`, `dss1-ie-5`, `dss1-ie-6`, `dss1-ie-7`.
- Locations: `plmn`, `lai`, `rai`, `sai`, `tai`, `ecgi`, `ncgi`, `5gs-tai`,
  `sgs-tai`, `sgs-ecgi`, `eps-tai-list`, `eps-tai-list-value`, `hi2-csg-id`, `gad`.
- Packet values: `eps-attach-type`, `eps-detach-type`, `nas-pdn-type`,
  `nas-request-type`, `nas-pti`, `gprs-nsapi`, `pdp-type`, `emm-cause`,
  `esm-cause`, `gtpv2-cause-code`, `tft`.

`isup-parameter` and `dss1-ie-*` require complete parameter TLVs; number,
bearer, cause, and NAS formats take only their contents. `sgs-tai` and
`sgs-ecgi` retain the TS 29.118 length octet after removing the IE identifier.
`eps-tai-list` likewise retains the length octet; `eps-tai-list-value` omits it.
`tft` starts at octet 3 of the TS 24.008 IE (operation/E/count), with no IEI/length.
`hi2-csg-id` uses the HI2 left-aligned 27-bit representation, not a right-aligned
integer. NR cell IDs contain 36 bits; NR tracking areas use three-octet TACs.

## Checking your schema

```sh
etsi-asn1-coverage first.asn dependencies.asn --root Module:Record > coverage.json
```

The `summary` counts **reachable byte-field paths**. Aliases/imports are followed,
all CHOICE alternatives are inspected, and lists use index `[0]`. Native ASN.1
integers, strings and enumerations need no byte decoder and are excluded.
BIT STRING fields remain `opaque` in this report because the byte-format
dispatcher does not interpret bit-length tuples. `mapped` means a dispatcher
exists, not that every possible value or protocol extension is understood.

The audit reports recursion, unresolved types and depth limits rather than
claiming coverage for them. Its entry limit raises an error instead of returning
an apparently complete truncated report. Source encoding/ROS-macro normalization
is the caller's responsibility, using the same preprocessing as the real decoder.
No source schema or captured data is modified by the audit.

The checked [schema inventory](schema-coverage-summary.json) records the exact
source hashes and roots used for the local Ericsson and Utimaco bundle audit.
Those source files are not distributed with this package. Counts include repeated
fields beneath different record alternatives; they are not runtime success rates.

Remaining opaque fields include whole MAP operations and supplementary-service
invocations, CC payloads, cryptographic keys/checksums, binary correlation IDs,
vendor/private data, and several PMIP/DSMIP/legacy addresses and QoS variants.
In particular, legacy `iP-Format` is not assumed to mean binary IPv4 solely from
its length. The supplied eight-octet `uLITimestamp` declaration is not interpreted
as NTP fractions: TS 29.060 specifies a four-octet seconds value, so a profile
must resolve the discrepancy. Whole SIP messages may contain binary bodies.

## Standards used

- [ETSI TS 101 671 V3.14.1, annex D](https://www.etsi.org/deliver/etsi_ts/101600_101699/101671/03.14.01_60/ts_101671v031401p.pdf): HI2 field definitions and encodings.
- [ITU-T Q.763 (12/1999)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-Q.763-199912-I!!PDF-E&lang=e&type=items): ISUP parameter framing, numbers, indicators and service information.
- [ITU-T Q.931 (05/1998)](https://www.itu.int/rec/dologin_pub.asp?id=T-REC-Q.931-199805-I!!PDF-E&lang=e&type=items): DSS1 IEs, cause/bearer/HLC encodings.
- [TS 29.274 V17.10.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/17.10.00_60/ts_129274v171000p.pdf): GTPv2 IE values, cause assignments and ULI extensions.
- [TS 24.008 V17.9.0](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/17.09.00_60/ts_124008v170900p.pdf): TFT components, PDP/request types and PCO.
- [TS 24.301 V17.12.0](https://www.etsi.org/deliver/etsi_ts/124300_124399/124301/17.12.00_60/ts_124301v171200p.pdf): NAS types/causes and TAI lists.
- [TS 29.118 V17.0.0](https://www.etsi.org/deliver/etsi_ts/129100_129199/129118/17.00.00_60/ts_129118v170000p.pdf): SGs TAI/ECGI IE framing.
- [TS 23.032 V18.1.0](https://www.etsi.org/deliver/etsi_ts/123000_123099/123032/18.01.00_60/ts_123032v180100p.pdf): classic GAD coordinate encodings.
- [TS 29.060 V17.2.0](https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/17.02.00_60/ts_129060v170200p.pdf): GTPv1 PDP type representation and ULI timestamp.

These references bound the implementation; they do not establish conformance
for every release or national extension. Add new formats with verified wire
layouts, complete-consumption checks, invalid-input vectors and raw-byte retention.

## Built-in path registry

The generated inventory below lists the exact suffix mappings in this release.
Longer suffixes take precedence; numeric list indices do not affect matching.

| Exact suffix | Format |
| --- | --- |
| `cCLink1Characteristics.release-Reason` | `q850-cause` |
| `cCLink2Characteristics.release-Reason` | `q850-cause` |
| `calledPartyNumber.dSS1-Format` | `dss1-called` |
| `calledPartyNumber.iSUP-Format` | `isup-called` |
| `calledPartyNumber.mAP-Format` | `map-address` |
| `callingPartyNumber.dSS1-Format` | `dss1-calling` |
| `callingPartyNumber.iSUP-Format` | `isup-calling` |
| `callingPartyNumber.mAP-Format` | `map-address` |
| `communication-Identity-Number` | `ascii-digits` |
| `conversationDuration` | `bcd-duration` |
| `csgIdentity` | `hi2-csg-id` |
| `eCGI` | `sgs-ecgi` |
| `ePS-DSMIP-SpecificParameters.iPv6careOfAddress` | `ipv6` |
| `ePS-GTPV2-specificParameters.aPN` | `gtpv2-apn` |
| `ePS-GTPV2-specificParameters.aPN-AMBR` | `gtpv2-ambr` |
| `ePS-GTPV2-specificParameters.attachType` | `eps-attach-type` |
| `ePS-GTPV2-specificParameters.bearerDeactivationCause` | `gtpv2-cause-code` |
| `ePS-GTPV2-specificParameters.detachType` | `eps-detach-type` |
| `ePS-GTPV2-specificParameters.ePSBearerIdentity` | `gtpv2-ebi` |
| `ePS-GTPV2-specificParameters.ePSBearerQoS` | `gtpv2-bearer-qos` |
| `ePS-GTPV2-specificParameters.failedBearerActivationReason` | `gtpv2-cause-code` |
| `ePS-GTPV2-specificParameters.failedBearerModReason` | `gtpv2-cause-code` |
| `ePS-GTPV2-specificParameters.failedEUTRANAttachReason` | `emm-cause` |
| `ePS-GTPV2-specificParameters.failedTAUReason` | `emm-cause` |
| `ePS-GTPV2-specificParameters.linkedEPSBearerId` | `gtpv2-ebi` |
| `ePS-GTPV2-specificParameters.pDNAddressAllocation` | `gtpv2-paa` |
| `ePS-GTPV2-specificParameters.pDNType` | `nas-pdn-type` |
| `ePS-GTPV2-specificParameters.procedureTransactionId` | `nas-pti` |
| `ePS-GTPV2-specificParameters.rATType` | `gtpv2-rat` |
| `ePS-GTPV2-specificParameters.requestType` | `nas-request-type` |
| `ePS-GTPV2-specificParameters.servingMMEaddress` | `utf-8` |
| `ePS-GTPV2-specificParameters.tFT` | `tft` |
| `ePS-GTPV2-specificParameters.trafficAggregateDescription` | `tft` |
| `ePS-GTPV2-specificParameters.uEReqPDNConnFailReason` | `esm-cause` |
| `ePS-MIP-SpecificParameters.careOfAddress` | `ipv4` |
| `ePS-MIP-SpecificParameters.foreignDomainAddress` | `ipv4` |
| `ePS-MIP-SpecificParameters.homeAddress` | `ipv4` |
| `ePS-MIP-SpecificParameters.homeAgentAddress` | `ipv4` |
| `ePS-PMIP-specificParameters.iPv4HomeAddress` | `ipv4` |
| `ePS-PMIP-specificParameters.iPv4careOfAddress` | `ipv4` |
| `ePS-PMIP-specificParameters.iPv6careOfAddress` | `ipv6` |
| `ePS-PMIP-specificParameters.servingNetwork` | `plmn` |
| `ePSCorrelationNumber` | `utf-8` |
| `ePSLocation.lastVisitedTAI` | `tai` |
| `ePSLocation.olduserLocationInfo` | `gtpv2-uli` |
| `ePSLocation.tAIlist` | `eps-tai-list` |
| `ePSLocation.userLocationInfo` | `gtpv2-uli` |
| `ePSlocationOfTheTarget.lastVisitedTAI` | `tai` |
| `ePSlocationOfTheTarget.olduserLocationInfo` | `gtpv2-uli` |
| `ePSlocationOfTheTarget.tAIlist` | `eps-tai-list` |
| `ePSlocationOfTheTarget.userLocationInfo` | `gtpv2-uli` |
| `gPRS-parameters.aPN` | `gtpv2-apn` |
| `gPRS-parameters.nSAPI` | `gprs-nsapi` |
| `gPRS-parameters.pDP-type` | `pdp-type` |
| `globalCellID` | `map-global-cell-id` |
| `gsmLocation.wGS84Coordinates` | `gad` |
| `heNBLocation.lastVisitedTAI` | `tai` |
| `heNBLocation.olduserLocationInfo` | `gtpv2-uli` |
| `heNBLocation.tAIlist` | `eps-tai-list` |
| `heNBLocation.userLocationInfo` | `gtpv2-uli` |
| `iP-value.iPBinaryAddress` | `ip-address` |
| `iPv4SubnetMask` | `ipv4` |
| `lEMF-Address.dSS1-Format` | `dss1-called` |
| `lEMF-Address.iSUP-Format` | `isup-called` |
| `lEMF-Address.mAP-Format` | `map-address` |
| `lawfulInterceptionIdentifier` | `ascii-text` |
| `locationOfTheTarget.e164-Number` | `isup-location` |
| `network-Element-Identifier.e164-Format` | `isup-calling` |
| `oldRAI` | `rai` |
| `operator-Identifier` | `ascii-text` |
| `pANI-Header-Info.access-Class` | `ascii-text` |
| `pANI-Header-Info.access-Type` | `ascii-text` |
| `pANI-Location.location.e164-Number` | `isup-location` |
| `pANI-Location.raw-Location` | `utf-8` |
| `partyIdentity.e164-Format` | `isup-calling` |
| `partyIdentity.imei` | `imei-tbcd` |
| `partyIdentity.imsi` | `imsi-tbcd` |
| `partyIdentity.msISDN` | `map-address` |
| `partyIdentity.nai` | `utf-8` |
| `partyIdentity.sip-uri` | `utf-8` |
| `partyIdentity.tel-uri` | `utf-8` |
| `partyIdentity.tel-url` | `utf-8` |
| `partyIdentity.x3GPPAssertedIdentity` | `utf-8` |
| `partyIdentity.xUI` | `utf-8` |
| `protConfigOptions.networkToUe` | `pco-network-to-ue` |
| `protConfigOptions.ueToNetwork` | `pco-ue-to-network` |
| `rAI` | `rai` |
| `release-Reason-Of-Intercepted-Call` | `q850-cause` |
| `ringingDuration` | `bcd-duration` |
| `sAI` | `sai` |
| `sdpAnswer` | `utf-8` |
| `sdpOffer` | `utf-8` |
| `services-Information.dSS1-parameters-codeset-0` | `dss1-ie-0` |
| `services-Information.iSUP-parameters` | `isup-parameter` |
| `servingS4-SGSN-address` | `utf-8` |
| `servingSystem.e164-Format` | `isup-calling` |
| `sipMessageHeaderAnswer` | `utf-8` |
| `sipMessageHeaderOffer` | `utf-8` |
| `standard-Supplementary-Services.dSS1-SS-parameters-codeset-0` | `dss1-ie-0` |
| `standard-Supplementary-Services.dSS1-SS-parameters-codeset-4` | `dss1-ie-4` |
| `standard-Supplementary-Services.dSS1-SS-parameters-codeset-5` | `dss1-ie-5` |
| `standard-Supplementary-Services.dSS1-SS-parameters-codeset-6` | `dss1-ie-6` |
| `standard-Supplementary-Services.dSS1-SS-parameters-codeset-7` | `dss1-ie-7` |
| `standard-Supplementary-Services.iSUP-SS-parameters` | `isup-parameter` |
| `tAI` | `sgs-tai` |
