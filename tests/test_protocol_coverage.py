"""Cross-profile protocol vectors, framing boundaries and coverage regressions."""
import ipaddress
import random
import unittest
from unittest.mock import patch

import asn1tools
import orjson

from etsi_asn1_decoder.decoder import ASN1Decoder, SUPPORTED_FIELD_FORMATS
from etsi_asn1_decoder.field_formats import ETSI_FIELD_FORMATS, builtin_field_format
from etsi_asn1_decoder.circuit import (decode_cause, decode_dss1_number,
    decode_bearer_capability, decode_high_layer, decode_dss1_ie)
from etsi_asn1_decoder.location import decode_area, decode_gad, decode_sgs_area, decode_tai_list
from etsi_asn1_decoder.packet import decode_tft, decode_pdp_type
from etsi_asn1_decoder.coverage import audit_schema


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        with patch.object(ASN1Decoder, 'compile_asn1_from_dir', return_value=None):
            self.decoder = ASN1Decoder('unused')

    def decode(self, fmt, wire):
        self.decoder.field_formats = {'value': fmt}
        return self.decoder.smart_decode_hex(wire, 'value')

    def test_realistic_cs_parameters_through_registry(self):
        value = {'services-Information': {
            'iSUP-parameters': [bytes.fromhex('020103'), bytes.fromhex('34029181')],
            'dSS1-parameters-codeset-0': [bytes.fromhex('04038090a3')]},
            'standard-Supplementary-Services': {'dSS1-SS-parameters-codeset-0': [bytes.fromhex('7d029181')]}}
        parsed = self.decoder.make_json_safe(value)
        services = parsed['services-Information']
        self.assertEqual(services['iSUP-parameters'][0]['decoded']['name'], '3.1 kHz audio')
        self.assertEqual(services['iSUP-parameters'][1]['decoded']['service'], 'telephony')
        bearer = services['dSS1-parameters-codeset-0'][0]['decoded']
        self.assertEqual((bearer['capability_name'], bearer['rate_kbps']), ('speech', 64))
        self.assertEqual(bearer['layers'][0]['protocol_name'], 'G.711 A-law')
        self.assertEqual(parsed['standard-Supplementary-Services']['dSS1-SS-parameters-codeset-0'][0]['decoded']['service'], 'telephony')

    def test_additional_cs_locations_durations_and_link_causes(self):
        parsed = self.decoder.make_json_safe({
            'callContentLinkInformation': {'cCLink1Characteristics': {'release-Reason': b'\x80\x90'}},
            'locationOfTheTarget': {'e164-Number': bytes.fromhex('8493214305')},
            'conversationDuration': bytes.fromhex('013059'), 'iPv4SubnetMask': bytes.fromhex('ffffff00')})
        self.assertEqual(parsed['callContentLinkInformation']['cCLink1Characteristics']['release-Reason']['cause'], 16)
        number = parsed['locationOfTheTarget']['e164-Number']
        self.assertEqual(number['number'], '12345')
        self.assertTrue(number['internal_network_routing_disallowed'])
        self.assertEqual(parsed['conversationDuration']['total_seconds'], 5459)
        self.assertEqual(parsed['iPv4SubnetMask']['address'], '255.255.255.0')
        self.assertTrue(self.decode('isup-location', b'\x00\x0b')['address_unavailable'])
        for wire in ('006000', '000060', 'f00000', '01020304', ''):
            self.assertEqual(self.decode('bcd-duration', bytes.fromhex(wire)), 'hex:' + wire)

    def test_cause_protocols_do_not_share_code_meanings(self):
        self.assertEqual(self.decode('emm-cause', b'\x1a')['name'], 'non-EPS authentication rejected')
        self.assertEqual(self.decode('esm-cause', b'\x1a')['name'], 'insufficient resources')
        self.assertEqual(self.decode('gtpv2-cause-code', b'\x1a')['unsupported'], True)
        self.assertEqual(self.decode('gtpv2-cause-code', b'\x83')['name'], 'paging restriction rejection')
        self.assertEqual(self.decode('nas-request-type', b'\x06')['name'], 'emergency bearer handover')
        for fmt in ('emm-cause', 'esm-cause', 'gtpv2-cause-code'):
            self.assertTrue(self.decode(fmt, b'\xff')['unsupported'])
            self.assertEqual(self.decode(fmt, b'\x10\x00'), 'hex:1000')

    def test_cause_extensions_diagnostics_and_non_itu_coding(self):
        self.assertEqual(decode_cause(bytes.fromhex('8090'))['cause_name'], 'normal call clearing')
        parsed = decode_cause(bytes.fromhex('0081910102'))
        self.assertEqual((parsed['recommendation'], parsed['cause']), (1, 17))
        self.assertEqual(parsed['diagnostics_raw_hex'], '0102')
        self.assertNotIn('cause_name', decode_cause(bytes.fromhex('a090')))
        for value in ('', '80', '0090', '8090ff00', '001190'):
            if value == '8090ff00':
                self.assertEqual(decode_cause(bytes.fromhex(value))['diagnostics_raw_hex'], 'ff00')
            else:
                self.assertIsNone(decode_cause(bytes.fromhex(value)))

    def test_dss1_numbers_are_ia5_with_optional_presentation(self):
        self.assertEqual(decode_dss1_number(b'\x91' + b'00123*#')['number'], '00123*#')
        parsed = decode_dss1_number(b'\x11\xa3' + b'123', True)
        self.assertEqual((parsed['number'], parsed['presentation'], parsed['screening']), ('123', 1, 3))
        self.assertEqual(decode_dss1_number(b'\x01\xc3', True)['number'], '')
        for data in (b'', b'\x11', b'\x11\x03', b'\x91\xff'):
            self.assertIsNone(decode_dss1_number(data, True))
        self.assertIsNone(decode_dss1_number(b'\x11\x83' + b'123'))

    def test_bearer_extensions_and_non_itu_are_not_silently_interpreted(self):
        parsed = decode_bearer_capability(bytes.fromhex('881882'))
        self.assertEqual(parsed['rate_kbps'], 128)
        self.assertEqual(decode_bearer_capability(bytes.fromhex('a090a3'))['unsupported'], True)
        self.assertIsNone(decode_bearer_capability(bytes.fromhex('809023')))
        self.assertIsNone(decode_bearer_capability(bytes.fromhex('8090a3a3')))
        parsed = decode_bearer_capability(bytes.fromhex('88902180'))
        self.assertTrue(parsed['layers'][0]['unsupported'])
        self.assertEqual(parsed['layers'][0]['extensions_raw_hex'], '80')
        self.assertIsNone(decode_high_layer(bytes.fromhex('9101')))

    def test_dss1_codesets_single_octets_and_unknown_tlvs(self):
        self.assertEqual(decode_dss1_ie(b'\xa1')['name'], 'Sending complete')
        self.assertEqual(decode_dss1_ie(b'\x9e')['target_codeset'], 6)
        self.assertFalse(decode_dss1_ie(b'\x9e')['locking'])
        self.assertTrue(decode_dss1_ie(bytes.fromhex('04038090a3'), 5)['unsupported'])
        unknown = decode_dss1_ie(bytes.fromhex('5501ff'))
        self.assertTrue(unknown['unsupported'])
        self.assertEqual(unknown['value_raw_hex'], 'ff')
        for data in ('a100', '04048090a3', '04028090a3', '04', ''):
            self.assertIsNone(decode_dss1_ie(bytes.fromhex(data)))

    def test_isup_access_transport_obeys_codeset_shifts_and_retains_order(self):
        body = bytes.fromhex('9d04038090a304038090a3')
        parsed = self.decode('isup-parameter', tlv(3, body))['decoded']['elements']
        self.assertEqual([p['codeset'] for p in parsed], [0, 5, 0])
        self.assertTrue(parsed[1]['unsupported'])
        self.assertEqual(parsed[2]['decoded']['capability_name'], 'speech')
        self.assertIn('decode_error', self.decode('isup-parameter', tlv(3, body + b'\x04')))

    def test_isup_common_numbers_cause_and_unknown_parameter(self):
        called = self.decode('isup-parameter', bytes.fromhex('04058410214305'))
        self.assertEqual(called['decoded']['number'], '12345')
        generic = self.decode('isup-parameter', bytes.fromhex('c006068413214305'))
        self.assertEqual(generic['decoded']['number_qualifier'], 6)
        self.assertEqual(generic['decoded']['raw_hex'], '068413214305')
        self.assertEqual(self.decode('isup-parameter', bytes.fromhex('12028090'))['decoded']['cause'], 16)
        self.assertTrue(self.decode('isup-parameter', bytes.fromhex('ee02aabb'))['unsupported'])
        self.assertEqual(self.decode('isup-parameter', bytes.fromhex('02010300')), 'hex:02010300')

    def test_location_layouts_do_not_confuse_sgs_length_with_plmn(self):
        plmn = bytes.fromhex('130062')
        values = [('rai', '000109', 'RAC', '9'), ('sai', '00010009', 'SAC', '9'),
                  ('tai', '0009', 'TAC', '9'), ('5gs-tai', '010203', 'TAC', '66051'),
                  ('ecgi', '01234567', 'ECI', '19088743'), ('ncgi', '0123456789', 'NCI', '4886718345')]
        for kind, tail, key, expected in values:
            result = decode_area(plmn + bytes.fromhex(tail), kind)
            self.assertEqual((result['MNC'], result[key]), ('260', expected))
        sgs = decode_sgs_area(b'\x05' + plmn + b'\x00\x09', 'tai')
        self.assertEqual(sgs['TAC'], '9')
        self.assertIsNone(decode_sgs_area(b'\x04' + plmn + b'\x00\x09', 'tai'))
        self.assertIsNone(decode_area(plmn + bytes.fromhex('f1234567'), 'ecgi'))
        self.assertIsNone(decode_area(bytes.fromhex('1f00620001'), 'tai'))

    def test_tai_list_all_three_forms_and_bounds(self):
        plmn = bytes.fromhex('130062')
        body = b'\x01' + plmn + bytes.fromhex('00010003')
        body += b'\x21' + plmn + bytes.fromhex('0004')
        body += b'\x40' + bytes.fromhex('26f1030007')
        result = decode_tai_list(bytes([len(body)]) + body)
        self.assertEqual([[v['TAC'] for v in p['areas']] for p in result['partial_lists']],
                         [['1', '3'], ['4', '5'], ['7']])
        for value in (b'', b'\x06\x60' + plmn + b'\x00\x00',
                      b'\x06\x21' + plmn + b'\xff\xff', bytes([len(body) - 1]) + body):
            self.assertIsNone(decode_tai_list(value))

    def test_uli_macro_and_extended_macro_fields(self):
        plmn = bytes.fromhex('26f103')
        for flag, value, bits, expected in ((0x40, '0abcde', 20, 703710),
                (0x80, '1abcde', 21, 1752286), (0x80, '81bcde', 18, 113886)):
            result = self.decode('gtpv2-uli', bytes([flag]) + plmn + bytes.fromhex(value))
            item = result['macroENodeB' if flag == 0x40 else 'extendedMacroENodeB']
            self.assertEqual((item['id_bits'], item['eNodeBID']), (bits, str(expected)))
        data = b'\xc0' + (plmn + bytes(3)) * 2
        self.assertEqual(self.decode('gtpv2-uli', data), 'hex:' + data.hex())

    def test_gad_classic_shapes_coordinates_and_negative_altitude(self):
        point = bytes.fromhex('400000400000')  # 45 N, 90 E.
        result = decode_gad(b'\x00' + point)
        self.assertEqual((result['latitude_degrees'], result['longitude_degrees']), (45, 90))
        south = decode_gad(bytes.fromhex('00c00000c00000'))
        self.assertEqual((south['latitude_degrees'], south['longitude_degrees']), (-45, -90))
        self.assertEqual(decode_gad(b'\x80' + point + b'\x80\x0a')['altitude_m'], -10)
        self.assertAlmostEqual(decode_gad(b'\x10' + point + b'\x01')['uncertainty_m'], 1)
        self.assertEqual(len(decode_gad(b'\x53' + point * 3)['points']), 3)
        self.assertEqual(decode_gad(b'\x30' + point + bytes([2, 1, 90, 95]))['confidence_percent'], 95)
        self.assertIn('altitude_uncertainty_m', decode_gad(b'\x90' + point + bytes([0, 1, 2, 1, 0, 2, 95])))
        self.assertEqual(decode_gad(b'\xa0' + point + bytes([0, 2, 1, 10, 20, 95]))['inner_radius_lower_bound_m'], 10)
        for value in (b'\x50', b'\x00' + point + b'\x00', b'\x10' + point + b'\xff',
                      b'\x30' + point + bytes([1, 2, 90, 95]), b'\xb0' + bytes(12)):
            self.assertIsNone(decode_gad(value))

    def test_nas_and_gtp_pdn_codes_are_separate(self):
        self.assertEqual(self.decode('nas-pdn-type', b'\x05')['name'], 'Non-IP')
        self.assertEqual(self.decode('gtpv2-paa', b'\x05')['pdn_type'], 'Ethernet')
        self.assertEqual(self.decode('eps-attach-type', b'\x06')['name'], 'EPS emergency attach')
        self.assertTrue(self.decode('eps-detach-type', b'\x09')['direction_required'])
        for code in ('0121', 'f121'):
            self.assertEqual(decode_pdp_type(bytes.fromhex(code))['name'], 'IPv4')
        self.assertEqual(decode_pdp_type(bytes.fromhex('0002'))['name'], 'Non-IP')
        self.assertIsNone(decode_pdp_type(bytes.fromhex('8121')))

    def test_tft_components_ipv4_port_ranges_and_parameters(self):
        components = bytes.fromhex('100a000001ffffff00300651005001bb')
        value = bytes([0x31, 0x31, 4, len(components)]) + components + bytes.fromhex('0102abcd')
        result = decode_tft(value)
        self.assertEqual(result['filters'][0]['components'][0]['address'], '10.0.0.1')
        self.assertEqual(result['filters'][0]['components'][2]['upper'], 443)
        self.assertEqual(result['parameters'][0]['content_raw_hex'], 'abcd')
        self.assertEqual(decode_tft(b'\xa2\x01\x04')['operation_name'], 'delete-filters')
        for bad in (b'', value[:-1], value + b'\x00', b'\x21', b'\x41', b'\xa2\x01\x01', b'\xc0'):
            self.assertIsNone(decode_tft(bad))

    def test_tft_unknown_or_bad_component_preserves_next_filter(self):
        unknown = bytes.fromhex('22300101ff3102023006')
        result = decode_tft(unknown)
        self.assertTrue(result['filters'][0]['components'][0]['unsupported'])
        self.assertEqual(result['filters'][1]['components'][0]['value'], 6)
        for content in (bytes.fromhex('5101bb0050'), bytes.fromhex('30063011'), bytes.fromhex('40')):
            value = bytes([0x21, 0x31, 1, len(content)]) + content
            self.assertIn('decode_error', decode_tft(value)['filters'][0])

    def test_tft_ipv6_ethernet_and_component_boundaries(self):
        values = [b'\x21' + ipaddress.IPv6Address('2001:db8::').packed + b'\x40',
                  bytes.fromhex('8100112233445583006485078786dd')]
        for content in values:
            value = bytes([0x21, 0x31, 1, len(content)]) + content
            self.assertIn('components', decode_tft(value)['filters'][0])
        invalid = b'\x21' + ipaddress.IPv6Address('2001:db8::').packed + b'\x81'
        self.assertIn('decode_error', decode_tft(bytes([0x21, 0x31, 1, len(invalid)]) + invalid)['filters'][0])

    def test_builtin_scope_overrides_and_every_format_is_valid(self):
        self.assertTrue(set(ETSI_FIELD_FORMATS.values()) <= SUPPORTED_FIELD_FORMATS)
        for path in ('other.tFT', 'rAIHash', 'partyIdentity.tel-uri.extra', 'other.iSUP-parameters'):
            self.assertIsNone(builtin_field_format(path))
        self.assertEqual(builtin_field_format('record.services-Information.iSUP-parameters[12]'), 'isup-parameter')
        self.decoder.use_builtin_formats = False
        self.assertEqual(self.decoder.smart_decode_hex(b'\x02\x01\x03', 'services-Information.iSUP-parameters'), 'hex:020103')
        self.decoder.field_formats = {'services-Information.iSUP-parameters': 'isup-parameter'}
        self.assertEqual(self.decoder.smart_decode_hex(b'\x02\x01\x03', 'services-Information.iSUP-parameters')['decoded']['name'], '3.1 kHz audio')

    def test_synthetic_ber_der_records_keep_parameter_boundaries(self):
        schema = '''Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN Record ::= SEQUENCE {
          services-Information SEQUENCE { iSUP-parameters SET OF OCTET STRING,
            dSS1-parameters-codeset-0 SET OF OCTET STRING },
          locationOfTheTarget SEQUENCE { rAI OCTET STRING, tAI OCTET STRING },
          partyIdentity SEQUENCE { tel-uri OCTET STRING } } END'''
        value = {'services-Information': {'iSUP-parameters': [bytes.fromhex('34029181')],
                 'dSS1-parameters-codeset-0': [bytes.fromhex('04038090a3')]},
                 'locationOfTheTarget': {'rAI': bytes.fromhex('26f103000109'), 'tAI': bytes.fromhex('0526f1030001')},
                 'partyIdentity': {'tel-uri': b'tel:+123'}}
        for codec in ('ber', 'der'):
            self.decoder.spec = asn1tools.compile_string(schema, codec)
            success, result = self.decoder.process_bytes(self.decoder.spec.encode('Record', value), roots='Record')
            self.assertTrue(success, result)
            content = result['content']
            self.assertEqual(content['locationOfTheTarget']['tAI']['TAC'], '1')
            self.assertEqual(content['services-Information']['iSUP-parameters'][0]['decoded']['service'], 'telephony')

    def test_random_and_all_truncations_never_raise_or_lose_raw(self):
        formats = ['isup-parameter', 'dss1-ie-0', 'q850-cause', 'dss1-bearer', 'dss1-high-layer',
                   'eps-tai-list', 'gtpv2-uli', 'gad', 'tft', 'sgs-ecgi', 'nas-pdn-type']
        rng = random.Random(763931)
        for i in range(2200):
            wire = bytes(rng.randrange(256) for _ in range(rng.randrange(80)))
            result = self.decode(formats[i % len(formats)], wire)
            orjson.dumps(result)
            self.assertEqual(result['raw_hex'] if isinstance(result, dict) else result[4:], wire.hex())
        for fmt, wire in [('isup-parameter', bytes.fromhex('34029181')), ('dss1-ie-0', bytes.fromhex('04038090a3')),
                          ('sgs-ecgi', bytes.fromhex('0726f10301234567'))]:
            for size in range(len(wire)):
                self.assertEqual(self.decode(fmt, wire[:size]), 'hex:' + wire[:size].hex())


class CoverageTests(unittest.TestCase):
    def test_aliases_imports_choices_lists_and_opaque_fields(self):
        modules = asn1tools.parse_string('''
        A DEFINITIONS ::= BEGIN Octets ::= OCTET STRING END
        B DEFINITIONS ::= BEGIN IMPORTS Octets FROM A;
        R ::= SEQUENCE { partyIdentity SEQUENCE { tel-uri Octets },
          services-Information SEQUENCE { iSUP-parameters SET OF Octets },
          raw Octets, bits BIT STRING, count INTEGER,
          sMS SEQUENCE { content Octets } } END''')
        result = audit_schema(modules, [('B', 'R')])
        self.assertEqual(result['summary'], {'mapped': 3, 'opaque': 2})
        self.assertEqual({r['path']: r['format'] for r in result['fields']}['services-Information.iSUP-parameters[0]'], 'isup-parameter')
        disabled = audit_schema(modules, [('B', 'R')], use_builtin_formats=False,
                                field_formats={'raw': 'utf-8', 'sMS.content': 'hex'})
        self.assertEqual(disabled['summary'], {'opaque': 4, 'mapped': 1})

    def test_recursion_unknown_types_and_limits_are_visible(self):
        modules = asn1tools.parse_string('M DEFINITIONS ::= BEGIN R ::= SEQUENCE { value OCTET STRING, next R OPTIONAL, missing Unknown } END')
        result = audit_schema(modules, [('M', 'R')])
        self.assertEqual(result['summary'], {'opaque': 1, 'recursive': 1, 'unresolved': 1})
        with self.assertRaises(ValueError):
            audit_schema(modules, [('M', 'R')], max_entries=1)
        with self.assertRaises(ValueError):
            audit_schema(modules, [('M', 'Missing')])
        with self.assertRaises(ValueError):
            audit_schema(modules, [('M', 'R')], field_formats={'value': 'guess'})


if __name__ == '__main__':
    unittest.main()
