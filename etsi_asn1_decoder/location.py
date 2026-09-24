"""Explicit location encodings: TS 23.003, 24.301, 29.118 and 23.032.

Wire variants have separate format names; size alone never selects a protocol.
"""


def decode_plmn(data):
    if len(data) != 3:
        return None
    a, b, c = data
    digits = (a & 15, a >> 4, b & 15, c & 15, c >> 4)
    if any(v > 9 for v in digits) or (b >> 4 > 9 and b >> 4 != 15):
        return None
    return {'type': 'plmn', 'MCC': ''.join(map(str, digits[:3])),
            'MNC': ''.join(map(str, digits[3:])) + (str(b >> 4) if b >> 4 != 15 else ''),
            'raw_hex': data.hex()}


def decode_area(data, kind):
    sizes = {'lai': 5, 'rai': 6, 'sai': 7, 'tai': 5, 'ecgi': 7, 'ncgi': 8, '5gs-tai': 6}
    if kind not in sizes or len(data) != sizes[kind]:
        return None
    plmn = decode_plmn(data[:3])
    if plmn is None:
        return None
    result = {'MCC': plmn['MCC'], 'MNC': plmn['MNC'], 'raw_hex': data.hex()}
    if kind in ('ecgi', 'ncgi'):
        if data[3] & 0xf0:
            return None
        result['ECI' if kind == 'ecgi' else 'NCI'] = str(int.from_bytes(data[3:], 'big'))
    else:
        result['TAC' if kind in ('tai', '5gs-tai') else 'LAC'] = str(int.from_bytes(
            data[3:] if kind == '5gs-tai' else data[3:5], 'big'))
        if kind in ('rai', 'sai'):
            result['RAC' if kind == 'rai' else 'SAC'] = str(int.from_bytes(data[5:], 'big'))
    return result


def decode_sgs_area(data, kind):
    # TS 29.118 IE with IEI excluded: length octet IS retained.
    if not data or len(data) != data[0] + 1:
        return None
    result = decode_area(data[1:], kind)
    if result is not None:
        result.update(raw_hex=data.hex(), length=data[0])
    return result


def decode_tai_list(data, with_length=True):
    """TS 24.301 partial lists 00/01/10, without IEI, retaining all entries."""
    if not data:
        return None
    body = data
    if with_length:
        if data[0] != len(data) - 1 or not 6 <= data[0] <= 96:
            return None
        body = data[1:]
    if not 6 <= len(body) <= 96:
        return None
    lists, pos = [], 0
    while pos < len(body):
        header = body[pos]
        pos += 1
        kind, count = (header >> 5) & 3, (header & 31) + 1
        if header & 128 or kind == 3 or count > 16:
            return None
        size = 5 * count if kind == 2 else 3 + 2 * (count if kind == 0 else 1)
        if pos + size > len(body):
            return None
        value = body[pos:pos + size]
        pos += size
        if kind == 2:
            items = [decode_area(value[i:i + 5], 'tai') for i in range(0, len(value), 5)]
        elif kind == 0:
            items = [decode_area(value[:3] + value[i:i + 2], 'tai') for i in range(3, len(value), 2)]
        else:
            first = int.from_bytes(value[3:], 'big')
            if first + count > 65536:
                return None
            items = [decode_area(value[:3] + (first + i).to_bytes(2, 'big'), 'tai') for i in range(count)]
        if any(v is None for v in items):
            return None
        lists.append({'list_type': kind, 'count': count, 'areas': items,
                      'raw_hex': bytes([header]).hex() + value.hex()})
    return {'partial_lists': lists, 'raw_hex': data.hex()}


def decode_csg(data):
    # HI2 CSGIdentity is left-aligned (27 bits, five padding bits).
    if len(data) != 4 or data[3] & 31:
        return None
    return {'CSGID': str(int.from_bytes(data, 'big') >> 5), 'raw_hex': data.hex()}


def decode_gad(data):
    """Seven classic TS 23.032 shapes. Coordinates are quantized estimates.

    High-accuracy/scalable variants require separate precision rules and remain
    unsupported rather than being interpreted using classic 24-bit coordinates.
    """
    if not data:
        return None
    kind = data[0] >> 4
    names = {0: 'ellipsoid-point', 1: 'uncertainty-circle', 3: 'uncertainty-ellipse',
             5: 'polygon', 8: 'point-with-altitude', 9: 'altitude-uncertainty-ellipsoid', 10: 'ellipsoid-arc'}
    lengths = {0: 7, 1: 8, 3: 11, 8: 9, 9: 14, 10: 13}
    if kind not in names:
        return None
    if kind == 5:
        count = data[0] & 15
        if not 3 <= count <= 15 or len(data) != 1 + count * 6:
            return None
    elif data[0] & 15 or len(data) != lengths[kind]:
        return None

    def point(value):
        latitude = int.from_bytes(value[:3], 'big')
        return {'latitude_degrees': (-1 if latitude & 0x800000 else 1) * (latitude & 0x7fffff) * 90 / 2**23,
                'longitude_degrees': int.from_bytes(value[3:], 'big', signed=True) * 360 / 2**24}

    def uncertainty(code, altitude=False):
        if code & 128:
            raise ValueError('Invalid uncertainty code')
        return (45 * (1.025**code - 1)) if altitude else (10 * (1.1**code - 1))

    result = {'shape': names[kind], 'raw_hex': data.hex()}
    if kind == 5:
        return dict(result, points=[point(data[i:i + 6]) for i in range(1, len(data), 6)])
    result.update(point(data[1:7]))
    try:
        if kind == 1:
            result.update(uncertainty_code=data[7], uncertainty_m=uncertainty(data[7]))
        if kind in (8, 9):
            altitude = int.from_bytes(data[7:9], 'big')
            result['altitude_m'] = (-1 if altitude & 0x8000 else 1) * (altitude & 0x7fff)
        if kind in (3, 9):
            pos = 7 if kind == 3 else 9
            major, minor, angle = data[pos:pos + 3]
            if angle >= 180 or minor > major:
                return None
            result.update(semi_major_uncertainty_code=major, semi_minor_uncertainty_code=minor,
                          semi_major_uncertainty_m=uncertainty(major),
                          semi_minor_uncertainty_m=uncertainty(minor), orientation_degrees=angle)
            if kind == 9:
                result.update(altitude_uncertainty_code=data[12], altitude_uncertainty_m=uncertainty(data[12], True))
        if kind == 10:
            if data[10] >= 180 or data[11] >= 180:
                return None
            result.update(inner_radius_lower_bound_m=int.from_bytes(data[7:9], 'big') * 5,
                          uncertainty_code=data[9], uncertainty_m=uncertainty(data[9]),
                          offset_angle_lower_bound_degrees=2 * data[10],
                          included_angle_upper_bound_degrees=2 * (data[11] + 1))
        if kind in (3, 9, 10):
            if data[-1] & 128:
                return None
            result['confidence_code'] = data[-1]
            result['confidence_percent'] = data[-1] if 1 <= data[-1] <= 100 else None
    except ValueError:
        return None
    return result


BYTE_FORMAT_DECODERS = {
    'plmn': decode_plmn,
    **{kind: (lambda value, kind=kind: decode_area(value, kind))
       for kind in ('lai', 'rai', 'sai', 'tai', 'ecgi', 'ncgi', '5gs-tai')},
    'sgs-tai': lambda value: decode_sgs_area(value, 'tai'),
    'sgs-ecgi': lambda value: decode_sgs_area(value, 'ecgi'),
    'eps-tai-list': decode_tai_list,
    'eps-tai-list-value': lambda value: decode_tai_list(value, False),
    'hi2-csg-id': decode_csg, 'gad': decode_gad,
}
