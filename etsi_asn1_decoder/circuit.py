"""Bounded Q.763 ISUP parameter and Q.931 DSS1 IE decoding.

Inputs are one complete TLV (or one single-octet DSS1 IE), not an ISUP/Q.931
message. Value-only formats are separate. Every compound result retains bytes.
Unknown variants are explicitly unsupported; framing errors return None.
References: Q.763 (12/1999), Q.931 (05/1998), Q.850 cause coding.
"""


CAUSE_NAMES = {1: 'unallocated number', 3: 'no route to destination',
    16: 'normal call clearing', 17: 'user busy', 18: 'no user responding',
    19: 'no answer', 21: 'call rejected', 22: 'number changed',
    27: 'destination out of order', 28: 'invalid number format',
    31: 'normal unspecified', 34: 'no circuit available', 38: 'network out of order',
    41: 'temporary failure', 42: 'switching equipment congestion',
    47: 'resource unavailable', 57: 'bearer capability not authorized',
    58: 'bearer capability not available', 63: 'service unavailable',
    65: 'bearer capability not implemented', 79: 'service not implemented',
    88: 'incompatible destination', 95: 'invalid message',
    96: 'missing mandatory information element', 97: 'message type not implemented',
    99: 'information element not implemented', 100: 'invalid information element contents',
    102: 'recovery on timer expiry', 111: 'protocol error', 127: 'interworking unspecified'}


def decode_cause(data):
    if len(data) < 2 or data[0] & 0x10:
        return None
    result = {'coding_standard': (data[0] >> 5) & 3, 'location': data[0] & 15,
              'raw_hex': data.hex()}
    pos = 1
    if not data[0] & 0x80:
        if len(data) < 3 or not data[1] & 0x80:
            return None
        result['recommendation'] = data[1] & 127
        pos += 1
    if not data[pos] & 0x80:
        return None
    result['cause'] = data[pos] & 127
    if result['coding_standard'] == 0:
        if result['cause'] in CAUSE_NAMES:
            result['cause_name'] = CAUSE_NAMES[result['cause']]
        else:
            result['unsupported'] = True
    else:
        result['unsupported'] = True
    if data[pos + 1:]:
        result['diagnostics_raw_hex'] = data[pos + 1:].hex()
        result['unsupported'] = True
    return result


def decode_dss1_number(data, calling=False):
    if not data:
        return None
    result = {'type_of_number': (data[0] >> 4) & 7,
              'numbering_plan': data[0] & 15, 'raw_hex': data.hex()}
    pos = 1
    if not data[0] & 128:
        if not calling or len(data) < 2 or not data[1] & 128 or data[1] & 0x1c:
            return None
        result.update(presentation=(data[1] >> 5) & 3, screening=data[1] & 3)
        pos += 1
    digits = data[pos:]
    # IA5 dialling characters. Preserve characters; do not invent an E.164 number.
    if any(c < 32 or c > 126 for c in digits):
        return None
    if not digits and (not calling or result.get('presentation') != 2):
        return None
    result['number'] = digits.decode('ascii')
    return result


def _extension_group(data, start):
    pos = start
    while pos < len(data):
        pos += 1
        if data[pos - 1] & 128:
            return data[start:pos], pos
    return None, start


def decode_bearer_capability(data):
    if len(data) < 2 or not data[0] & 128:
        return None
    result = {'coding_standard': (data[0] >> 5) & 3, 'raw_hex': data.hex()}
    if result['coding_standard']:
        return dict(result, unsupported=True, content_raw_hex=data[1:].hex())
    capability, mode, rate = data[0] & 31, (data[1] >> 5) & 3, data[1] & 31
    result.update(information_transfer_capability=capability, transfer_mode=mode,
                  information_transfer_rate=rate)
    names = {0: 'speech', 8: 'unrestricted digital', 9: 'restricted digital',
             16: '3.1 kHz audio', 17: 'digital with tones', 24: 'video'}
    if capability in names:
        result['capability_name'] = names[capability]
    else:
        result['unsupported'] = True
    if mode in (0, 2):
        result['transfer_mode_name'] = 'circuit' if mode == 0 else 'packet'
    else:
        result['unsupported'] = True
    rates = {16: 64, 17: 128, 19: 384, 21: 1536, 23: 1920}
    group, pos = _extension_group(data, 1)
    if group is None:
        return None
    if mode == 0 and rate in rates:
        result['rate_kbps'] = rates[rate]
    elif mode == 0 and rate == 24 and len(group) == 2 and group[1] & 127 >= 2:
        result['rate_multiplier'] = group[1] & 127
        result['rate_kbps'] = result['rate_multiplier'] * 64
    elif not (mode == 2 and rate == 0):
        result['unsupported'] = True
    if len(group) > 1 and not (rate == 24 and len(group) == 2):
        result.update(transfer_extensions_raw_hex=group[1:].hex(), unsupported=True)
    layers, previous = [], 0
    while pos < len(data):
        group, pos = _extension_group(data, pos)
        if group is None:
            return None
        layer = (group[0] >> 5) & 3
        if not layer or layer <= previous:
            return None
        previous = layer
        item = {'layer': layer, 'protocol': group[0] & 31, 'raw_hex': group.hex()}
        names = {1: 'V.110', 2: 'G.711 mu-law', 3: 'G.711 A-law', 4: 'G.721',
                 5: 'H.221/H.242', 6: 'H.223/H.245', 7: 'non-ITU rate adaptation',
                 8: 'V.120', 9: 'X.31 HDLC'}
        if layer == 1 and item['protocol'] in names:
            item['protocol_name'] = names[item['protocol']]
        else:
            item['unsupported'] = True
        if len(group) > 1:
            item.update(extensions_raw_hex=group[1:].hex(), unsupported=True)
        layers.append(item)
    result['layers'] = layers
    return result


def decode_high_layer(data):
    if len(data) < 2 or not data[0] & 128:
        return None
    result = {'coding_standard': (data[0] >> 5) & 3,
              'interpretation': (data[0] >> 2) & 7, 'presentation_method': data[0] & 3,
              'raw_hex': data.hex()}
    if result['coding_standard']:
        return dict(result, unsupported=True, content_raw_hex=data[1:].hex())
    group, pos = _extension_group(data, 1)
    if group is None or pos != len(data):
        return None
    result['characteristics'] = [v & 127 for v in group]
    names = {1: 'telephony', 4: 'fax group 2/3', 33: 'fax group 4 class I',
             36: 'fax group 4 classes II/III', 50: 'syntax-based videotex',
             51: 'videotex interworking', 53: 'telex', 56: 'message handling',
             65: 'OSI application', 66: 'FTAM', 96: 'videotelephony',
             97: 'videoconferencing', 98: 'audiographic conferencing', 104: 'multimedia'}
    if result['interpretation'] == 4 and result['presentation_method'] == 1 and group[0] & 127 in names:
        result['service'] = names[group[0] & 127]
    else:
        result['unsupported'] = True
    if len(group) > 1:
        result['unsupported'] = True
    return result


def decode_notification(data):
    group, pos = _extension_group(data, 0)
    if group is None or pos != len(data):
        return None
    names = {0: 'user suspended', 1: 'user resumed', 2: 'bearer service change',
             4: 'call completion delay', 66: 'conference established', 67: 'conference disconnected',
             68: 'other party added', 69: 'isolated', 70: 'reattached', 96: 'call waiting',
             104: 'diversion activated', 105: 'call transfer alerting', 106: 'call transfer active',
             121: 'remote hold', 122: 'remote retrieval', 123: 'call diverting'}
    values = [{'value': v & 127, **({'name': names[v & 127]} if v & 127 in names
                                 else {'unsupported': True})} for v in group]
    return {'notifications': values, 'raw_hex': data.hex()}


DSS1_NAMES = {4: 'Bearer capability', 8: 'Cause', 0x14: 'Call state',
    0x18: 'Channel identification', 0x1c: 'Facility', 0x1e: 'Progress indicator',
    0x27: 'Notification indicator', 0x28: 'Display', 0x29: 'Date/time',
    0x2c: 'Keypad facility', 0x34: 'Signal', 0x4c: 'Connected number',
    0x4d: 'Connected subaddress', 0x6c: 'Calling party number', 0x6d: 'Calling party subaddress',
    0x70: 'Called party number', 0x71: 'Called party subaddress', 0x74: 'Redirecting number',
    0x7c: 'Low layer compatibility', 0x7d: 'High layer compatibility', 0x7e: 'User-user'}


def decode_dss1_ie(data, codeset=0):
    if not data:
        return None
    tag = data[0]
    result = {'protocol': 'DSS1', 'codeset': codeset, 'id': tag, 'raw_hex': data.hex()}
    if tag & 128:
        if len(data) != 1:
            return None
        result['single_octet'] = True
        if tag in (0xa0, 0xa1):
            result['name'] = 'More data' if tag == 0xa0 else 'Sending complete'
        elif tag & 0xf0 == 0x90:
            result.update(name='Codeset shift', target_codeset=tag & 7, locking=not bool(tag & 8))
        else:
            result['unsupported'] = True
        return result
    if len(data) < 2 or len(data) != 2 + data[1]:
        return None
    value = data[2:]
    result.update(length=len(value), value_raw_hex=value.hex())
    if codeset != 0:
        return dict(result, unsupported=True)
    if tag in DSS1_NAMES:
        result['name'] = DSS1_NAMES[tag]
    decoders = {4: decode_bearer_capability, 8: decode_cause, 0x7d: decode_high_layer,
        0x27: decode_notification, 0x70: decode_dss1_number,
        0x6c: lambda v: decode_dss1_number(v, True), 0x4c: lambda v: decode_dss1_number(v, True)}
    if tag in decoders:
        parsed = decoders[tag](value)
        if parsed is None:
            result['decode_error'] = 'Malformed or unsupported IE value'
        else:
            result['decoded'] = parsed
    elif tag in (0x28, 0x2c) and value and all(32 <= b <= 126 for b in value):
        result['decoded'] = {'text': value.decode('ascii')}
    elif tag == 0x14 and len(value) == 1:
        result['decoded'] = {'coding_standard': value[0] >> 6, 'state': value[0] & 63}
    elif tag == 0x1e and len(value) == 2 and value[0] & 128 and value[1] & 128:
        result['decoded'] = {'coding_standard': (value[0] >> 5) & 3,
                             'location': value[0] & 15, 'description': value[1] & 127}
    elif tag in (0x4d, 0x6d, 0x71) and value and value[0] & 128:
        result['decoded'] = {'type': (value[0] >> 4) & 7, 'odd': bool(value[0] & 8),
                             'address_raw_hex': value[1:].hex(), 'unsupported': True}
    elif tag == 0x7e and value:
        result['decoded'] = {'protocol_discriminator': value[0],
                             'user_information_raw_hex': value[1:].hex(), 'unsupported': True}
    else:
        result['unsupported'] = True
    return result


ISUP_NAMES = {2: 'Transmission medium requirement', 3: 'Access transport',
    4: 'Called party number', 6: 'Nature of connection indicators', 7: 'Forward call indicators',
    8: 'Optional forward call indicators', 9: 'Calling party category', 10: 'Calling party number',
    11: 'Redirecting number', 12: 'Redirection number', 16: 'Continuity indicators',
    17: 'Backward call indicators', 18: 'Cause indicators', 19: 'Redirection information',
    0x1d: 'User service information', 0x20: 'User-to-user information', 0x21: 'Connected number',
    0x24: 'Event information', 0x28: 'Original called number', 0x29: 'Optional backward call indicators',
    0x2c: 'Generic notification indicator', 0x31: 'Propagation delay counter',
    0x33: 'User service information prime', 0x34: 'User teleservice information',
    0x35: 'Transmission medium requirement prime', 0x36: 'Call diversion information',
    0x38: 'Message compatibility information', 0x39: 'Parameter compatibility information',
    0x3d: 'Hop counter', 0x3f: 'Location number', 0xc0: 'Generic number'}


def decode_location_number(data, number_decoder):
    # Q.763 3.30: calling-style digits/presentation, with an INN indicator.
    if data == b'\x00\x0b':
        return {'number': None, 'presentation': 2, 'screening': 3,
                'address_unavailable': True, 'raw_hex': data.hex()}
    result = number_decoder(data, calling=True)
    if result is not None:
        result['internal_network_routing_disallowed'] = bool(data[1] & 128)
    return result


def decode_duration(data):
    """HI2 duration: three BCD octets HHMMSS, most-significant digit first."""
    if len(data) != 3 or any((b >> 4) > 9 or (b & 15) > 9 for b in data):
        return None
    hours, minutes, seconds = ((b >> 4) * 10 + (b & 15) for b in data)
    if minutes > 59 or seconds > 59:
        return None
    return {'hours': hours, 'minutes': minutes, 'seconds': seconds,
            'total_seconds': hours * 3600 + minutes * 60 + seconds, 'raw_hex': data.hex()}


def decode_isup_parameter(data, number_decoder):
    if len(data) < 2 or len(data) != data[1] + 2:
        return None
    tag, value = data[0], data[2:]
    result = {'protocol': 'ISUP', 'id': tag, 'length': len(value),
              'value_raw_hex': value.hex(), 'raw_hex': data.hex()}
    if tag in ISUP_NAMES:
        result['name'] = ISUP_NAMES[tag]
    parsed = None
    if tag in (4, 10, 11, 12, 0x21, 0x28, 0x3f, 0xc0):
        body = value[1:] if tag == 0xc0 else value
        parsed = (decode_location_number(body, number_decoder) if tag == 0x3f
                  else number_decoder(body, calling=tag not in (4, 12)))
        if parsed is not None:
            if tag == 0xc0:
                parsed.update(number_qualifier=value[0], raw_hex=value.hex())
            if tag in (11, 0x28):
                parsed.pop('screening', None)  # These bits are spare in these parameters.
    elif tag == 18:
        parsed = decode_cause(value)
    elif tag in (0x1d, 0x33):
        parsed = decode_bearer_capability(value)
    elif tag == 0x34:
        parsed = decode_high_layer(value)
    elif tag == 0x2c:
        parsed = decode_notification(value)
    elif tag in (2, 0x35) and len(value) == 1:
        parsed = {'value': value[0]}
        names = {0: 'speech', 2: '64 kbit/s unrestricted', 3: '3.1 kHz audio',
                 6: '64 kbit/s preferred', 8: '2 x 64 kbit/s', 9: '384 kbit/s',
                 10: '1536 kbit/s', 11: '1920 kbit/s'}
        if value[0] in names:
            parsed['name'] = names[value[0]]
        else:
            parsed['unsupported'] = True
    elif tag == 6 and len(value) == 1:
        parsed = {'satellite_indicator': value[0] & 3, 'continuity_check': (value[0] >> 2) & 3,
                  'echo_control_device': (value[0] >> 4) & 1, 'spare_bits': value[0] >> 5}
    elif tag == 0x24 and len(value) == 1:
        parsed = {'event': value[0] & 127, 'presentation_restricted': bool(value[0] & 128)}
    elif tag == 0x29 and len(value) == 1:
        parsed = {'in_band_information': bool(value[0] & 1), 'call_diversion_possible': bool(value[0] & 2),
                  'segmentation': bool(value[0] & 4), 'mlpp_user': bool(value[0] & 8),
                  'national_bits': value[0] >> 4}
    elif tag == 0x31 and len(value) == 2:
        parsed = {'delay_ms': int.from_bytes(value, 'big')}
    elif tag == 0x3d and len(value) == 1 and not value[0] & 0xe0:
        parsed = {'hops': value[0] & 31}
    elif tag == 0x13 and len(value) == 2:
        parsed = {'redirecting_indicator': value[0] & 7, 'original_reason': value[0] >> 4,
                  'counter': value[1] & 7, 'reason': value[1] >> 4,
                  'spare_bits': [bool(value[0] & 8), bool(value[1] & 8)]}
    elif tag == 3:
        # Access transport contains a sequence of complete DSS1 information elements.
        elements, pos, codeset = [], 0, 0
        next_codeset = None
        while pos < len(value):
            size = 1 if value[pos] & 128 else (2 + value[pos + 1] if pos + 1 < len(value) else 0)
            if not size or pos + size > len(value):
                break
            element = decode_dss1_ie(value[pos:pos + size], codeset if next_codeset is None else next_codeset)
            if element is None:
                break
            next_codeset = None
            if element.get('name') == 'Codeset shift':
                if element['locking']:
                    codeset = element['target_codeset']
                else:
                    next_codeset = element['target_codeset']
            elements.append(element)
            pos += size
        if pos == len(value) and elements and next_codeset is None:
            parsed = {'elements': elements}
    else:
        return dict(result, unsupported=True)
    if parsed is None:
        result['decode_error'] = 'Malformed or unsupported parameter value'
    else:
        result['decoded'] = parsed
    return result


BYTE_FORMAT_DECODERS = {
    'bcd-duration': decode_duration,
    'q850-cause': decode_cause, 'dss1-called': decode_dss1_number,
    'dss1-calling': lambda value: decode_dss1_number(value, True),
    'dss1-bearer': decode_bearer_capability, 'dss1-high-layer': decode_high_layer,
    **{f'dss1-ie-{codeset}': (lambda value, codeset=codeset: decode_dss1_ie(value, codeset))
       for codeset in (0, 4, 5, 6, 7)},
}
