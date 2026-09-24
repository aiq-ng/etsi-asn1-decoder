"""Built-in ETSI field/format mappings, independent of enclosing record names.

Source: ETSI TS 101 671 V3.14.1, annex D, PartyInformation,
CallingPartyNumber and CalledPartyNumber (pp. 89-90 and 112-113).
https://www.etsi.org/deliver/etsi_ts/101600_101699/101671/03.14.01_60/ts_101671v031401p.pdf

Match complete, case-sensitive path components, never byte patterns or leaf
name substrings. Custom profiles can override any exact full path, including
with 'hex'. This is a registry of known ETSI definitions, not schema inference.
"""

import re


ETSI_FIELD_FORMATS = {
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
}


def builtin_field_format(path):
    # SEQUENCE OF adds indices to the JSON traversal path, not to field names.
    fields = tuple(re.sub(r"(?:\[\d+\])+$", "", part) for part in path.split("."))
    return ETSI_FIELD_FORMATS.get(fields[-2:])
