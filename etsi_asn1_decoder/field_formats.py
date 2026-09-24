"""Built-in ETSI field/format mappings, independent of enclosing record names.

Source: ETSI TS 101 671 V3.14.1, annex D, PartyInformation,
CallingPartyNumber, CalledPartyNumber, LawfulInterceptionIdentifier and
CommunicationIdentifier, Network-Identifier, Network-Element-Identifier and
Location (pp. 88-90, 92, 97 and 111-115).
https://www.etsi.org/deliver/etsi_ts/101600_101699/101671/03.14.01_60/ts_101671v031401p.pdf

GlobalCellId wire format: TS 29.002 V17.2.0, MAP-CommonDataTypes, p. 465.
https://www.etsi.org/deliver/etsi_ts/129000_129099/129002/17.02.00_60/ts_129002v170200p.pdf

Match complete, case-sensitive path components, never byte patterns or leaf
name substrings. Custom profiles can override any exact full path, including
with 'hex'. This is a registry of known ETSI definitions, not schema inference.
"""

import re


ETSI_FIELD_FORMATS = {
    # These exact ETSI field names also occur in standalone decoded roots.
    # LIID ASCII is recommended, not mandatory; binary profiles retain hex.
    ("lawfulInterceptionIdentifier",): "ascii-text",
    ("communication-Identity-Number",): "ascii-digits",
    ("operator-Identifier",): "ascii-text",
    ("globalCellID",): "map-global-cell-id",
    # Correlation identifiers use strict UTF-8 when valid, else retain hex.
    # This is a presentation policy, not a claim that every sender uses text.
    ("ePSCorrelationNumber",): "utf-8",
    ("iP-value", "iPBinaryAddress"): "ip-address",
    ("ePS-GTPV2-specificParameters", "aPN"): "gtpv2-apn",
    ("ePS-GTPV2-specificParameters", "aPN-AMBR"): "gtpv2-ambr",
    ("ePS-GTPV2-specificParameters", "ePSBearerIdentity"): "gtpv2-ebi",
    ("ePS-GTPV2-specificParameters", "linkedEPSBearerId"): "gtpv2-ebi",
    ("ePS-GTPV2-specificParameters", "rATType"): "gtpv2-rat",
    ("ePS-GTPV2-specificParameters", "ePSBearerQoS"): "gtpv2-bearer-qos",
    ("ePS-GTPV2-specificParameters", "pDNAddressAllocation"): "gtpv2-paa",
    ("ePSlocationOfTheTarget", "userLocationInfo"): "gtpv2-uli",
    ("ePSlocationOfTheTarget", "olduserLocationInfo"): "gtpv2-uli",
    ("protConfigOptions", "ueToNetwork"): "pco-ue-to-network",
    ("protConfigOptions", "networkToUe"): "pco-network-to-ue",
    ("network-Element-Identifier", "e164-Format"): "isup-calling",
    ("servingSystem", "e164-Format"): "isup-calling",
    ("partyIdentity", "imsi"): "imsi-tbcd",
    ("partyIdentity", "imei"): "imei-tbcd",
    ("partyIdentity", "msISDN"): "map-address",
    ("partyIdentity", "e164-Format"): "isup-calling",
    ("partyIdentity", "sip-uri"): "utf-8",
    ("partyIdentity", "tel-url"): "utf-8",
    ("callingPartyNumber", "iSUP-Format"): "isup-calling",
    ("calledPartyNumber", "iSUP-Format"): "isup-called",
    ("callingPartyNumber", "mAP-Format"): "map-address",
    ("calledPartyNumber", "mAP-Format"): "map-address",
    # CS value-only numbers and complete service parameter TLVs are distinct.
    ("callingPartyNumber", "dSS1-Format"): "dss1-calling",
    ("calledPartyNumber", "dSS1-Format"): "dss1-called",
    ("lEMF-Address", "dSS1-Format"): "dss1-called",
    ("lEMF-Address", "iSUP-Format"): "isup-called",
    ("lEMF-Address", "mAP-Format"): "map-address",
    ("services-Information", "iSUP-parameters"): "isup-parameter",
    ("services-Information", "dSS1-parameters-codeset-0"): "dss1-ie-0",
    ("standard-Supplementary-Services", "iSUP-SS-parameters"): "isup-parameter",
    ("standard-Supplementary-Services", "dSS1-SS-parameters-codeset-0"): "dss1-ie-0",
    ("standard-Supplementary-Services", "dSS1-SS-parameters-codeset-4"): "dss1-ie-4",
    ("standard-Supplementary-Services", "dSS1-SS-parameters-codeset-5"): "dss1-ie-5",
    ("standard-Supplementary-Services", "dSS1-SS-parameters-codeset-6"): "dss1-ie-6",
    ("standard-Supplementary-Services", "dSS1-SS-parameters-codeset-7"): "dss1-ie-7",
    ("release-Reason-Of-Intercepted-Call",): "q850-cause",
    ("cCLink1Characteristics", "release-Reason"): "q850-cause",
    ("cCLink2Characteristics", "release-Reason"): "q850-cause",
    ("ringingDuration",): "bcd-duration",
    ("conversationDuration",): "bcd-duration",
    ("locationOfTheTarget", "e164-Number"): "isup-location",
    ("pANI-Location", "location", "e164-Number"): "isup-location",
    ("iPv4SubnetMask",): "ipv4",
    # Exact standardized location leaves; similarly spelled/vendor fields do not match.
    ("rAI",): "rai", ("oldRAI",): "rai", ("sAI",): "sai",
    ("tAI",): "sgs-tai", ("eCGI",): "sgs-ecgi",
    ("gsmLocation", "wGS84Coordinates"): "gad",
    ("ePSlocationOfTheTarget", "lastVisitedTAI"): "tai",
    ("ePSlocationOfTheTarget", "tAIlist"): "eps-tai-list",
    ("ePSLocation", "userLocationInfo"): "gtpv2-uli",
    ("ePSLocation", "olduserLocationInfo"): "gtpv2-uli",
    ("ePSLocation", "lastVisitedTAI"): "tai",
    ("ePSLocation", "tAIlist"): "eps-tai-list",
    ("heNBLocation", "userLocationInfo"): "gtpv2-uli",
    ("heNBLocation", "olduserLocationInfo"): "gtpv2-uli",
    ("heNBLocation", "lastVisitedTAI"): "tai",
    ("heNBLocation", "tAIlist"): "eps-tai-list",
    ("csgIdentity",): "hi2-csg-id",
    ("gPRS-parameters", "aPN"): "gtpv2-apn",
    ("gPRS-parameters", "pDP-type"): "pdp-type",
    ("gPRS-parameters", "nSAPI"): "gprs-nsapi",
    ("ePS-GTPV2-specificParameters", "attachType"): "eps-attach-type",
    ("ePS-GTPV2-specificParameters", "detachType"): "eps-detach-type",
    ("ePS-GTPV2-specificParameters", "pDNType"): "nas-pdn-type",
    ("ePS-GTPV2-specificParameters", "requestType"): "nas-request-type",
    ("ePS-GTPV2-specificParameters", "procedureTransactionId"): "nas-pti",
    ("ePS-GTPV2-specificParameters", "tFT"): "tft",
    ("ePS-GTPV2-specificParameters", "trafficAggregateDescription"): "tft",
    ("ePS-GTPV2-specificParameters", "failedTAUReason"): "emm-cause",
    ("ePS-GTPV2-specificParameters", "failedEUTRANAttachReason"): "emm-cause",
    ("ePS-GTPV2-specificParameters", "uEReqPDNConnFailReason"): "esm-cause",
    ("ePS-GTPV2-specificParameters", "failedBearerActivationReason"): "gtpv2-cause-code",
    ("ePS-GTPV2-specificParameters", "failedBearerModReason"): "gtpv2-cause-code",
    ("ePS-GTPV2-specificParameters", "bearerDeactivationCause"): "gtpv2-cause-code",
    ("ePS-GTPV2-specificParameters", "servingMMEaddress"): "utf-8",
    ("servingS4-SGSN-address",): "utf-8",
    # PMIP/DSMIP wire layouts differ; only independently specified fields are mapped.
    ("ePS-PMIP-specificParameters", "servingNetwork"): "plmn",
    ("ePS-PMIP-specificParameters", "iPv4HomeAddress"): "ipv4",
    ("ePS-PMIP-specificParameters", "iPv4careOfAddress"): "ipv4",
    ("ePS-PMIP-specificParameters", "iPv6careOfAddress"): "ipv6",
    ("ePS-DSMIP-SpecificParameters", "iPv6careOfAddress"): "ipv6",
    ("ePS-MIP-SpecificParameters", "homeAddress"): "ipv4",
    ("ePS-MIP-SpecificParameters", "careOfAddress"): "ipv4",
    ("ePS-MIP-SpecificParameters", "homeAgentAddress"): "ipv4",
    ("ePS-MIP-SpecificParameters", "foreignDomainAddress"): "ipv4",
    # URI/header fields with specified text contents, not arbitrary message bodies.
    ("partyIdentity", "tel-uri"): "utf-8",
    ("partyIdentity", "nai"): "utf-8",
    ("partyIdentity", "x3GPPAssertedIdentity"): "utf-8",
    ("partyIdentity", "xUI"): "utf-8",
    ("pANI-Header-Info", "access-Type"): "ascii-text",
    ("pANI-Header-Info", "access-Class"): "ascii-text",
    ("pANI-Location", "raw-Location"): "utf-8",
    ("sipMessageHeaderOffer",): "utf-8",
    ("sipMessageHeaderAnswer",): "utf-8",
    ("sdpOffer",): "utf-8",
    ("sdpAnswer",): "utf-8",
}


def builtin_field_format(path):
    # SEQUENCE OF adds indices to the JSON traversal path, not to field names.
    fields = tuple(re.sub(r"(?:\[\d+\])+$", "", part) for part in path.split("."))
    for size in range(min(len(fields), max(map(len, ETSI_FIELD_FORMATS), default=0)), 0, -1):
        fmt = ETSI_FIELD_FORMATS.get(fields[-size:])
        if fmt is not None:
            return fmt
    return None
