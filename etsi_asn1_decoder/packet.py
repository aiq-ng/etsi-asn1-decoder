"""Value-only NAS and traffic-filter formats (TS 24.301 and TS 24.008).

Unknown codes retain the numeric value and raw bytes with unsupported=True.
No ASN.1 field name or byte length is used to guess the protocol.
"""
import ipaddress


def octet_code(data, names, protocol):
    if len(data) != 1:
        return None
    result = {'protocol': protocol, 'value': data[0], 'raw_hex': data.hex()}
    if data[0] in names:
        result['name'] = names[data[0]]
    else:
        result['unsupported'] = True
    return result


def nas_type(data, names, protocol):
    if len(data) != 1 or data[0] & 0xf8:
        return None
    return octet_code(data, names, protocol)


def detach_type(data):
    if len(data) != 1 or data[0] & 0xf0:
        return None
    return {'type_value': data[0] & 7, 'bit4': bool(data[0] & 8),
            'direction_required': True, 'raw_hex': data.hex()}


def decode_pdp_type(data):
    # HI2 permits the NAS (0000 spare) and GTPv1 (1111 spare) forms.
    if len(data) != 2 or data[0] >> 4 not in (0, 15):
        return None
    names = {(0, 1): 'PPP', (1, 0x21): 'IPv4', (1, 0x57): 'IPv6', (1, 0x8d): 'IPv4v6',
             (0, 2): 'Non-IP'}
    key = (data[0] & 15, data[1])
    result = {'organization': key[0], 'type_number': data[1], 'raw_hex': data.hex(),
              'encoding': 'GTPv1' if data[0] >> 4 == 15 else 'NAS'}
    if key in names:
        result['name'] = names[key]
    else:
        result['unsupported'] = True
    return result


COMPONENTS = {
    0x10: ('remote_ipv4', 8), 0x11: ('local_ipv4', 8), 0x20: ('remote_ipv6_mask', 32),
    0x21: ('remote_ipv6_prefix', 17), 0x23: ('local_ipv6_prefix', 17),
    0x30: ('protocol_or_next_header', 1), 0x40: ('local_port', 2),
    0x41: ('local_port_range', 4), 0x50: ('remote_port', 2),
    0x51: ('remote_port_range', 4), 0x60: ('security_parameter_index', 4),
    0x70: ('tos_or_traffic_class', 2), 0x80: ('flow_label', 3),
    0x81: ('destination_mac', 6), 0x82: ('source_mac', 6),
    0x83: ('c_tag_vid', 2), 0x84: ('s_tag_vid', 2),
    0x85: ('c_tag_pcp_dei', 1), 0x86: ('s_tag_pcp_dei', 1), 0x87: ('ethertype', 2),
}


def _components(data):
    result, pos, seen = [], 0, set()
    while pos < len(data):
        start, kind = pos, data[pos]
        pos += 1
        if kind not in COMPONENTS:
            result.append({'id': kind, 'unsupported': True, 'remaining_raw_hex': data[start:].hex()})
            return result
        name, size = COMPONENTS[kind]
        if pos + size > len(data) or kind in seen:
            return None
        seen.add(kind)
        value = data[pos:pos + size]
        pos += size
        item = {'id': kind, 'name': name, 'raw_hex': data[start:pos].hex()}
        if kind in (0x10, 0x11, 0x20):
            split = size // 2
            item.update(address=str(ipaddress.ip_address(bytes(value[:split]))),
                        mask=str(ipaddress.ip_address(bytes(value[split:]))))
        elif kind in (0x21, 0x23):
            if value[16] > 128:
                return None
            item.update(address=str(ipaddress.IPv6Address(bytes(value[:16]))), prefix_length=value[16])
        elif kind in (0x41, 0x51):
            lower, upper = int.from_bytes(value[:2], 'big'), int.from_bytes(value[2:], 'big')
            if lower > upper:
                return None
            item.update(lower=lower, upper=upper)
        elif kind == 0x70:
            item.update(value=value[0], mask=value[1])
        elif kind in (0x81, 0x82):
            item['address'] = ':'.join(f'{b:02x}' for b in value)
        elif kind in (0x85, 0x86):
            if value[0] & 0xf0:
                return None
            item.update(pcp=(value[0] >> 1) & 7, dei=value[0] & 1)
        else:
            if kind in (0x80, 0x83, 0x84) and value[0] & 0xf0:
                return None
            item['value'] = int.from_bytes(value, 'big')
        result.append(item)
    # Mutually exclusive alternatives defined for the same component purpose.
    for alternatives in ({0x10, 0x20, 0x21}, {0x11, 0x23}, {0x40, 0x41}, {0x50, 0x51}):
        if len(seen & alternatives) > 1:
            return None
    ether = next((v['value'] for v in result if v['id'] == 0x87), None)
    if ether is not None and ether not in (0x0800, 0x86dd) and any(k <= 0x80 for k in seen):
        return None
    return result


def decode_tft(data):
    if not data or len(data) > 255:
        return None
    operation, parameters, count = data[0] >> 5, bool(data[0] & 16), data[0] & 15
    if operation == 7 or (operation in (0, 2, 6) and count) or (operation in (1, 3, 4, 5) and not count):
        return None
    if (operation == 0 and parameters) or (operation == 6 and not parameters):
        return None
    result = {'operation': operation, 'operation_name': {
        0: 'ignore', 1: 'create', 2: 'delete', 3: 'add-filters', 4: 'replace-filters',
        5: 'delete-filters', 6: 'no-operation'}[operation], 'filters': [],
        'parameters': [], 'raw_hex': data.hex()}
    pos, ids = 1, set()
    for _ in range(count):
        if pos >= len(data):
            return None
        identity = data[pos] & 15
        if identity in ids:
            return None
        ids.add(identity)
        if operation == 5:
            if data[pos] & 0xf0:
                return None
            result['filters'].append({'id': identity, 'raw_hex': data[pos:pos + 1].hex()})
            pos += 1
            continue
        if pos + 3 > len(data) or data[pos] & 0xc0:
            return None
        size = data[pos + 2]
        if not size or pos + 3 + size > len(data):
            return None
        value = data[pos + 3:pos + 3 + size]
        components = _components(value)
        item = {'id': identity, 'direction': (data[pos] >> 4) & 3, 'precedence': data[pos + 1],
                'content_raw_hex': value.hex(), 'raw_hex': data[pos:pos + 3 + size].hex()}
        if components is None:
            item['decode_error'] = 'Malformed or conflicting filter components'
        else:
            item['components'] = components
        result['filters'].append(item)
        pos += 3 + size
    if parameters:
        if pos == len(data):
            return None
        while pos < len(data):
            if pos + 2 > len(data) or pos + 2 + data[pos + 1] > len(data):
                return None
            size = data[pos + 1]
            result['parameters'].append({'id': data[pos], 'length': size, 'unsupported': True,
                'content_raw_hex': data[pos + 2:pos + 2 + size].hex(),
                'raw_hex': data[pos:pos + 2 + size].hex()})
            pos += 2 + size
    return result if pos == len(data) else None


EMM_CAUSES = {2: 'IMSI unknown in HSS', 3: 'illegal UE', 5: 'IMEI not accepted', 6: 'illegal ME',
    7: 'EPS services not allowed', 8: 'EPS and non-EPS services not allowed',
    9: 'UE identity unavailable', 10: 'implicitly detached', 11: 'PLMN not allowed',
    12: 'tracking area not allowed', 13: 'roaming not allowed in tracking area',
    14: 'EPS services not allowed in PLMN', 15: 'no suitable cells',
    16: 'MSC temporarily unreachable', 17: 'network failure', 18: 'CS unavailable',
    19: 'ESM failure', 20: 'MAC failure', 21: 'synchronization failure', 22: 'congestion',
    23: 'security capability mismatch', 24: 'security mode rejected', 25: 'CSG unauthorized',
    26: 'non-EPS authentication rejected', 31: 'redirect to 5GCN',
    35: 'service unauthorized in PLMN', 36: 'IAB operation unauthorized',
    39: 'CS temporarily unavailable', 40: 'no active EPS bearer',
    42: 'severe network failure', 78: 'PLMN disallowed at UE location'}

# TS 24.301 9.9.3.9 / 9.9.4.4. Unknown/reserved codes are never coerced.
NAS_PROTOCOL_CAUSES = {95: 'semantic message error', 96: 'invalid mandatory data',
    97: 'unsupported message type', 98: 'message type invalid in current state',
    99: 'unsupported IE', 100: 'conditional IE error', 101: 'message invalid in current state',
    111: 'unspecified protocol error'}
EMM_CAUSES.update(NAS_PROTOCOL_CAUSES)
ESM_CAUSES = {**NAS_PROTOCOL_CAUSES,
    8: 'operator barring', 26: 'insufficient resources', 27: 'APN missing or unknown',
    28: 'unknown PDN type', 29: 'authentication failed', 30: 'gateway rejected request',
    31: 'unspecified rejection', 32: 'service unsupported', 33: 'service not subscribed',
    34: 'service temporarily unavailable', 35: 'PTI in use', 36: 'regular deactivation',
    37: 'EPS QoS rejected', 38: 'network failure', 39: 'reactivation requested',
    41: 'TFT semantic error', 42: 'TFT syntax error', 43: 'invalid bearer identity',
    44: 'filter semantic error', 45: 'filter syntax error', 47: 'PTI mismatch',
    49: 'cannot disconnect last PDN', 50: 'IPv4 required', 51: 'IPv6 required',
    52: 'single-address bearers required', 53: 'ESM information missing',
    54: 'PDN connection absent', 55: 'duplicate APN connections disallowed',
    56: 'network request collision', 57: 'IPv4v6 required', 58: 'Non-IP required',
    59: 'QCI unsupported', 60: 'bearer handling unsupported', 61: 'Ethernet required',
    65: 'bearer limit reached', 66: 'APN unavailable in RAT/PLMN', 81: 'invalid PTI',
    112: 'APN restriction conflicts with active bearer', 113: 'multiple accesses disallowed'}

# TS 29.274 8.4: the HI2 fields carry only the cause octet, not the complete IE.
GTP_CAUSES = {
    2: 'local detach', 3: 'complete detach', 4: 'RAT changed to non-3GPP',
    5: 'ISR deactivated', 6: 'access node error indication', 7: 'IMSI-only detach',
    8: 'reactivation requested', 9: 'APN reconnection disallowed',
    10: 'access changed to 3GPP', 11: 'PDN inactivity expiry', 12: 'PGW unresponsive',
    13: 'network failure', 14: 'QoS mismatch', 15: 'EPS to 5GS mobility',
    16: 'accepted', 17: 'partially accepted', 18: 'PDN type changed by network preference',
    19: 'PDN type changed for single-address bearer', 64: 'context absent',
    65: 'malformed message', 66: 'peer version unsupported', 67: 'invalid length',
    68: 'service unsupported', 69: 'invalid mandatory IE', 70: 'missing mandatory IE',
    72: 'system failure', 73: 'resources unavailable', 74: 'TFT semantic error',
    75: 'TFT syntax error', 76: 'filter semantic error', 77: 'filter syntax error',
    78: 'APN missing or unknown', 80: 'GRE key absent', 81: 'relocation failed',
    82: 'RAT denied', 83: 'preferred PDN type unsupported', 84: 'address pool exhausted',
    85: 'context without TFT already active', 86: 'protocol unsupported',
    87: 'UE unresponsive', 88: 'UE refusal', 89: 'service denied', 90: 'UE paging failed',
    91: 'memory unavailable', 92: 'authentication failed', 93: 'APN not subscribed',
    94: 'unspecified rejection', 95: 'P-TMSI signature mismatch', 96: 'unknown IMSI/IMEI',
    97: 'TAD semantic error', 98: 'TAD syntax error', 100: 'peer unresponsive',
    101: 'network request collision', 102: 'paging blocked by suspension',
    103: 'conditional IE absent', 104: 'APN restriction conflicts with active connection',
    105: 'invalid combined message length', 106: 'forwarding unsupported',
    107: 'invalid peer reply', 108: 'GTPv1 fallback', 109: 'invalid peer',
    110: 'mobility procedure in progress', 111: 'change extends beyond S1-U bearers',
    112: 'PMIPv6 rejection', 113: 'APN congestion', 114: 'bearer handling unsupported',
    115: 'UE already reattached', 116: 'duplicate APN connections disallowed',
    117: 'target access restricted', 119: 'VPLMN policy rejection',
    120: 'GTP-C congestion', 121: 'late overlapping request', 122: 'request timed out',
    123: 'UE temporarily unreachable in power saving', 124: 'NAS redirection disrupted relocation',
    125: 'OCS/AAA authorization denied', 126: 'multiple accesses disallowed',
    127: 'UE capability insufficient', 128: 'S1-U path failure', 129: '5GC disallowed',
    130: 'PGW conflicts with subscribed slice', 131: 'paging restriction rejection'}


BYTE_FORMAT_DECODERS = {
    'eps-attach-type': lambda data: nas_type(data, {1: 'EPS attach', 2: 'combined EPS/IMSI attach',
        3: 'EPS RLOS attach', 6: 'EPS emergency attach'}, 'NAS'),
    'eps-detach-type': detach_type,
    'nas-pdn-type': lambda data: nas_type(data, {1: 'IPv4', 2: 'IPv6', 3: 'IPv4v6',
        5: 'Non-IP', 6: 'Ethernet'}, 'NAS'),
    'emm-cause': lambda data: octet_code(data, EMM_CAUSES, 'EMM'),
    'esm-cause': lambda data: octet_code(data, ESM_CAUSES, 'ESM'),
    'gtpv2-cause-code': lambda data: octet_code(data, GTP_CAUSES, 'GTPv2'),
    'nas-request-type': lambda data: nas_type(data, {1: 'initial request', 2: 'handover',
        3: 'RLOS', 4: 'emergency', 6: 'emergency bearer handover'}, 'NAS request type'),
    'nas-pti': lambda data: {'value': data[0], 'raw_hex': data.hex()} if len(data) == 1 else None,
    'gprs-nsapi': lambda data: {'value': data[0], 'raw_hex': data.hex()} if len(data) == 1 and 5 <= data[0] <= 15 else None,
    'pdp-type': decode_pdp_type,
    'tft': decode_tft,
}
