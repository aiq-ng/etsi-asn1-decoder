"""Built-in ETSI field/format mappings, independent of enclosing record names.

Source: ETSI TS 101 671 V3.14.1, annex D, PartyInformation,
CallingPartyNumber, CalledPartyNumber, LawfulInterceptionIdentifier and
CommunicationIdentifier (pp. 88-90, 97 and 111-115).
https://www.etsi.org/deliver/etsi_ts/101600_101699/101671/03.14.01_60/ts_101671v031401p.pdf

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
    for size in (2, 1):
        fmt = ETSI_FIELD_FORMATS.get(fields[-size:])
        if fmt is not None:
            return fmt
    return None
