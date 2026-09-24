"""Value-only EPS/GTPv2 decoders, without IE type/length/instance headers.

References: TS 29.274 V17.10.0 clauses 8.6-8.21; TS 24.008 V17.9.0
clause 10.5.6.3; RFCs 1332, 1334 and 1877. Unsupported/malformed values
return None so the caller preserves every byte as hex. Successful compound
results retain raw_hex, including unrecognized PCO contents.
"""
import ipaddress
import re


def decode_apn(data, *, text_only=False, labels_only=False):
    """APN DNS labels, or an explicitly identified dotted-ASCII vendor form."""
    if not 1 <= len(data) <= 100:
        return None

    def valid_label(label):
        return re.fullmatch(rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is not None

    if not text_only:
        labels, pos = [], 0
        while pos < len(data):
            size = data[pos]
            pos += 1
            if not 1 <= size <= 63 or pos + size > len(data):
                break
            label = data[pos:pos + size]
            if not valid_label(label):
                break
            labels.append(label.decode('ascii'))
            pos += size
        else:
            if labels:
                return {'name': '.'.join(labels), 'encoding': 'dns-labels', 'raw_hex': data.hex()}
        if labels_only:
            return None
    # Field-specific compatibility with senders delivering a textual APN.
    # A binary label stream containing control bytes cannot pass this branch.
    labels = data.split(b'.')
    if all(valid_label(label) for label in labels):
        return {'name': data.decode('ascii'), 'encoding': 'dotted-ascii', 'raw_hex': data.hex()}
    return None


def decode_ambr(data):
    if len(data) != 8:
        return None
    return {'uplink_kbps': int.from_bytes(data[:4], 'big'),
            'downlink_kbps': int.from_bytes(data[4:], 'big'), 'raw_hex': data.hex()}


def decode_ebi(data):
    if len(data) != 1 or not 1 <= data[0] <= 15:
        return None
    return {'value': data[0], 'raw_hex': data.hex()}


RAT_TYPES = {
    1: 'UTRAN', 2: 'GERAN', 3: 'WLAN', 4: 'GAN', 5: 'HSPA-Evolution',
    6: 'EUTRAN', 7: 'Virtual', 8: 'EUTRAN-NB-IoT', 9: 'LTE-M', 10: 'NR',
    11: 'WB-E-UTRAN-LEO', 12: 'WB-E-UTRAN-MEO', 13: 'WB-E-UTRAN-GEO',
    14: 'WB-E-UTRAN-OTHERSAT', 15: 'EUTRAN-NB-IoT-LEO',
    16: 'EUTRAN-NB-IoT-MEO', 17: 'EUTRAN-NB-IoT-GEO', 18: 'EUTRAN-NB-IoT-OTHERSAT',
    19: 'LTE-M-LEO', 20: 'LTE-M-MEO', 21: 'LTE-M-GEO', 22: 'LTE-M-OTHERSAT',
}


def decode_rat(data):
    if len(data) != 1 or data[0] not in RAT_TYPES:
        return None
    return {'value': data[0], 'name': RAT_TYPES[data[0]], 'raw_hex': data.hex()}


def decode_bearer_qos(data):
    if len(data) != 22 or data[0] & 0x82:
        return None
    result = {'priority_level': (data[0] >> 2) & 15,
              'pre_emption_capability': (data[0] >> 6) & 1,
              'pre_emption_vulnerability': data[0] & 1,
              'qci': data[1], 'raw_hex': data.hex()}
    for offset, name in ((2, 'maximum_uplink_kbps'), (7, 'maximum_downlink_kbps'),
                         (12, 'guaranteed_uplink_kbps'), (17, 'guaranteed_downlink_kbps')):
        result[name] = int.from_bytes(data[offset:offset + 5], 'big')
    return result


def decode_paa(data):
    if not data or data[0] & 0xf8:
        return None
    kind = data[0]
    lengths = {1: 5, 2: 18, 3: 22, 4: 1, 5: 1}
    if len(data) != lengths.get(kind):
        return None
    result = {'pdn_type': {1: 'IPv4', 2: 'IPv6', 3: 'IPv4v6', 4: 'Non-IP', 5: 'Ethernet'}[kind],
              'raw_hex': data.hex()}
    if kind in (2, 3):
        if data[1] != 64:  # The GTPv2 PAA IPv6 prefix length is fixed at /64.
            return None
        result.update(ipv6_prefix_length=data[1], ipv6_address=str(ipaddress.IPv6Address(bytes(data[2:18]))))
    if kind in (1, 3):
        result['ipv4_address'] = str(ipaddress.IPv4Address(bytes(data[-4:])))
    return result


def decode_uli(data, decode_plmn):
    """Decode base ULI fields and the mutually exclusive macro-eNodeB forms."""
    if not data or not data[0] or data[0] & 0xc0 == 0xc0:
        return None
    layouts = (('CGI', 7), ('SAI', 7), ('RAI', 7), ('TAI', 5), ('ECGI', 7), ('LAI', 5),
               ('macroENodeB', 6), ('extendedMacroENodeB', 6))
    expected = 1 + sum(size for bit, (_, size) in enumerate(layouts) if data[0] & (1 << bit))
    if len(data) != expected:
        return None
    result, pos = {'flags': data[0], 'raw_hex': data.hex()}, 1
    for bit, (kind, size) in enumerate(layouts):
        if not data[0] & (1 << bit):
            continue
        raw = data[pos:pos + size]
        pos += size
        plmn = decode_plmn(raw[:3])
        if plmn is None:
            return None
        value = {'MCC': plmn['MCC'], 'MNC': plmn['MNC'], 'raw_hex': raw.hex()}
        if kind in ('macroENodeB', 'extendedMacroENodeB'):
            bits = 20 if kind == 'macroENodeB' else (18 if raw[3] & 128 else 21)
            if raw[3] & (0xf0 if kind == 'macroENodeB' else 0x60):
                return None
            identity = int.from_bytes(raw[3:], 'big') & ((1 << bits) - 1)
            value.update(eNodeBID=str(identity), id_bits=bits)
            # Short IDs carry three ignored bits; preserve them without folding
            # them into the actual 18-bit identity (TS 29.274 8.21.8).
            if bits == 18:
                value['ignored_bits'] = (raw[3] >> 2) & 7
        elif kind == 'ECGI':
            if raw[3] & 0xf0:
                return None
            value['ECI'] = str(int.from_bytes(raw[3:], 'big'))
        else:
            value['TAC' if kind == 'TAI' else 'LAC'] = str(int.from_bytes(raw[3:5], 'big'))
            if kind in ('CGI', 'SAI'):
                value['CellID' if kind == 'CGI' else 'SAC'] = str(int.from_bytes(raw[5:], 'big'))
            elif kind == 'RAI':
                if raw[6] != 255:
                    return None
                value['RAC'] = str(raw[5])
        result[kind] = value
    return result


def _ppp_packet(data, protocol):
    """Decode PAP and IPCP; preserve unknown codes/options and credential bytes."""
    if len(data) < 4 or int.from_bytes(data[2:4], 'big') != len(data):
        return None
    result = {'code': data[0], 'identifier': data[1], 'length': len(data), 'raw_hex': data.hex()}
    body = data[4:]
    if protocol == 0xc023:
        result['protocol'] = 'PAP'
        if data[0] == 1:
            if not body or len(body) < body[0] + 2:
                return None
            peer_length = body[0]
            password_length = body[peer_length + 1]
            if len(body) != peer_length + password_length + 2:
                return None
            result.update(code_name='Authenticate-Request', peer_id_raw_hex=body[1:peer_length + 1].hex(),
                          password_raw_hex=body[peer_length + 2:].hex())
        elif data[0] in (2, 3):
            if not body or len(body) != body[0] + 1:
                return None
            result.update(code_name='Authenticate-Ack' if data[0] == 2 else 'Authenticate-Nak',
                          message_raw_hex=body[1:].hex())
        else:
            result.update(unsupported=True, content_raw_hex=body.hex())
    else:
        result['protocol'] = 'IPCP'
        if data[0] not in (1, 2, 3, 4):
            result.update(unsupported=True, content_raw_hex=body.hex())
            return result
        result['code_name'] = {1: 'Configure-Request', 2: 'Configure-Ack', 3: 'Configure-Nak',
                               4: 'Configure-Reject'}[data[0]]
        result['options'] = []
        pos = 0
        names = {3: 'ip_address', 129: 'primary_dns_server', 130: 'primary_nbns_server',
                 131: 'secondary_dns_server', 132: 'secondary_nbns_server'}
        while pos < len(body):
            if len(body) - pos < 2 or not 2 <= body[pos + 1] <= len(body) - pos:
                return None
            kind, length = body[pos:pos + 2]
            value = body[pos + 2:pos + length]
            option = {'type': kind, 'length': length, 'raw_hex': body[pos:pos + length].hex()}
            if kind in names:
                if length != 6:
                    return None
                option.update(name=names[kind], address=str(ipaddress.IPv4Address(bytes(value))))
            else:
                option.update(unsupported=True, content_raw_hex=value.hex())
            result['options'].append(option)
            pos += length
    return result


_ADDRESS_CONTAINERS = {1: ('P-CSCF IPv6 address', 16), 3: ('DNS server IPv6 address', 16),
                       12: ('P-CSCF IPv4 address', 4), 13: ('DNS server IPv4 address', 4)}
_LONG_DOWNLINK_LENGTHS = {0x23, 0x24, 0x30, 0x31, 0x32, 0x41}


def decode_pco(data, direction):
    """PCO from octet three, with explicit direction for container semantics."""
    if direction not in ('ue-to-network', 'network-to-ue'):
        raise ValueError('PCO direction must be ue-to-network or network-to-ue')
    if not 1 <= len(data) <= 251 or not data[0] & 0x80 or data[0] & 0x78:
        return None
    result = {'configuration_protocol': data[0] & 7, 'direction': direction,
              'entries': [], 'raw_hex': data.hex()}
    pos = 1
    while pos < len(data):
        if len(data) - pos < 3:
            return None
        start = pos
        kind = int.from_bytes(data[pos:pos + 2], 'big')
        size_len = 2 if (kind == 0x41 or (direction == 'network-to-ue' and kind in _LONG_DOWNLINK_LENGTHS)) else 1
        pos += 2
        if pos + size_len > len(data):
            return None
        length = int.from_bytes(data[pos:pos + size_len], 'big')
        pos += size_len
        if pos + length > len(data):
            return None
        value = data[pos:pos + length]
        pos += length
        entry = {'id': f'0x{kind:04x}', 'length': length, 'content_raw_hex': value.hex(),
                 'raw_hex': data[start:pos].hex()}
        if kind in (0xc023, 0x8021):
            entry['name'] = 'PAP' if kind == 0xc023 else 'IPCP'
            packet = _ppp_packet(value, kind)
            if packet is None:
                entry['decode_error'] = 'Malformed PPP packet or options'
            else:
                entry['decoded'] = packet
        elif kind in _ADDRESS_CONTAINERS:
            name, size = _ADDRESS_CONTAINERS[kind]
            entry['name'] = name
            if direction == 'ue-to-network':
                entry['name'] += ' request'
                if length == 0:
                    entry['request'] = True
                else:
                    entry['decode_error'] = 'Address request must have empty contents'
            elif length == size:
                entry['address'] = str(ipaddress.ip_address(bytes(value)))
            else:
                entry['decode_error'] = 'Invalid address length'
        elif kind == 0x10:
            entry['name'] = 'IPv4 link MTU'
            if direction == 'ue-to-network':
                entry['name'] += ' request'
                if length == 0:
                    entry['request'] = True
                else:
                    entry['decode_error'] = 'MTU request must have empty contents'
            elif length == 2:
                entry['mtu'] = int.from_bytes(value, 'big')
            else:
                entry['decode_error'] = 'Invalid MTU length'
        elif kind == 5:
            entry['name'] = ('Network-requested bearer control support' if direction == 'ue-to-network'
                             else 'Selected bearer control mode')
            if direction == 'ue-to-network' and length == 0:
                entry['supported'] = True
            elif direction == 'network-to-ue' and length == 1 and value[0] in (1, 2):
                entry['mode'] = value[0]
                entry['mode_name'] = 'MS only' if value[0] == 1 else 'MS/NW'
            else:
                entry['decode_error'] = 'Invalid bearer control contents'
        else:
            entry['unsupported'] = True
        result['entries'].append(entry)
    return result


BYTE_FORMAT_DECODERS = {
    'gtpv2-apn': decode_apn,
    'apn-dns-labels': lambda data: decode_apn(data, labels_only=True),
    'apn-text': lambda data: decode_apn(data, text_only=True),
    'gtpv2-ambr': decode_ambr,
    'gtpv2-ebi': decode_ebi,
    'gtpv2-rat': decode_rat,
    'gtpv2-bearer-qos': decode_bearer_qos,
    'gtpv2-paa': decode_paa,
    'pco-ue-to-network': lambda data: decode_pco(data, 'ue-to-network'),
    'pco-network-to-ue': lambda data: decode_pco(data, 'network-to-ue'),
}
