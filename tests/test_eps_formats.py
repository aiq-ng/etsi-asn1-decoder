"""Synthetic GTPv2 vectors and BER/DER integration, without operator captures."""
import ipaddress
import random
import unittest
from unittest.mock import patch

import asn1tools
import orjson

from etsi_asn1_decoder.decoder import ASN1Decoder
from etsi_asn1_decoder.eps import (decode_apn, decode_ambr, decode_ebi, decode_rat,
    decode_bearer_qos, decode_paa, decode_pco, decode_uli, BYTE_FORMAT_DECODERS)


GTP = 'ePS-GTPV2-specificParameters.'
PCO = bytes.fromhex('80c0230c0100000c037765620377656280211001000010810600000000830600000000000d00000500001000')
ULI = bytes.fromhex('1826f10375d826f10301b96d53')
QOS = bytes.fromhex('4c090000000000000000000000000000000000000000')


def entry(kind, value, size_len=1):
    return kind.to_bytes(2, 'big') + len(value).to_bytes(size_len, 'big') + value


class EPSFormatTests(unittest.TestCase):
    def setUp(self):
        with patch.object(ASN1Decoder, 'compile_asn1_from_dir', return_value=None):
            self.decoder = ASN1Decoder('unused')

    def test_apn_standard_labels_and_dotted_ascii_are_distinguished(self):
        for wire, encoding in ((b'\x03web\x04gprs\x0amtnnigeria\x03net', 'dns-labels'),
                               (b'web.gprs.mtnnigeria.net', 'dotted-ascii')):
            result = self.decoder.smart_decode_hex(wire, GTP + 'aPN')
            self.assertEqual(result, {'name': 'web.gprs.mtnnigeria.net', 'encoding': encoding, 'raw_hex': wire.hex()})
        self.assertIsNone(decode_apn(b'web.example', labels_only=True))
        self.assertIsNone(decode_apn(b'\x03web', text_only=True))
        self.assertEqual(decode_apn(b'Internet')['name'], 'Internet')

    def test_apn_malformed_labels_never_lose_bytes(self):
        for wire in (b'', b'\x05abc', b'\x03web\x00', b'\xc0\x01', b'web..net', b'.web', b'web.',
                     b'web\x00net', b'web net', b'\xff', b'-web', b'web-', b'a' * 101,
                     b'\x40' + b'a' * 64, b'\x03web\x04net'):
            with self.subTest(wire=wire):
                self.assertIsNone(decode_apn(wire))
                self.assertEqual(self.decoder.smart_decode_hex(wire, GTP + 'aPN'), 'hex:' + wire.hex())

    def test_ambr_units_and_unsigned_boundaries(self):
        result = decode_ambr(bytes.fromhex('0040000000400000'))
        self.assertEqual((result['uplink_kbps'], result['downlink_kbps']), (4194304, 4194304))
        result = decode_ambr(bytes.fromhex('ffffffff00000000'))
        self.assertEqual((result['uplink_kbps'], result['downlink_kbps']), (4294967295, 0))

    def test_ebi_and_rat_codes(self):
        self.assertEqual(decode_ebi(b'\x05')['value'], 5)
        for number in range(1, 16):
            self.assertEqual(decode_ebi(bytes([number]))['value'], number)
        for number in (0, 16, 255):
            self.assertIsNone(decode_ebi(bytes([number])))
        self.assertEqual(decode_rat(b'\x06')['name'], 'EUTRAN')
        self.assertEqual(decode_rat(b'\x0a')['name'], 'NR')
        self.assertIsNone(decode_rat(b'\xff'))

    def test_bearer_qos_flags_and_five_octet_rates(self):
        qos = decode_bearer_qos(QOS)
        self.assertEqual(qos['qci'], 9)
        self.assertEqual(qos['priority_level'], 3)
        self.assertEqual(qos['pre_emption_capability'], 1)
        self.assertEqual(qos['pre_emption_vulnerability'], 0)
        rates = (1, 2, (1 << 40) - 1, 1 << 32)
        wire = b'\x4d\x05' + b''.join(x.to_bytes(5, 'big') for x in rates)
        qos = decode_bearer_qos(wire)
        self.assertEqual([qos[k] for k in ('maximum_uplink_kbps', 'maximum_downlink_kbps',
                         'guaranteed_uplink_kbps', 'guaranteed_downlink_kbps')], list(rates))
        self.assertEqual(qos['pre_emption_vulnerability'], 1)
        for spare in (0x80, 2):
            self.assertIsNone(decode_bearer_qos(bytes([QOS[0] | spare]) + QOS[1:]))

    def test_paa_ipv4_ipv6_dual_stack_and_no_ip_variants(self):
        v4 = ipaddress.IPv4Address('10.120.155.21').packed
        v6 = ipaddress.IPv6Address('2001:db8::1').packed
        self.assertEqual(decode_paa(b'\x01' + v4)['ipv4_address'], '10.120.155.21')
        self.assertEqual(decode_paa(b'\x02\x40' + v6)['ipv6_address'], '2001:db8::1')
        dual = decode_paa(b'\x03\x40' + v6 + v4)
        self.assertEqual((dual['ipv6_prefix_length'], dual['ipv4_address']), (64, '10.120.155.21'))
        self.assertEqual(decode_paa(b'\x04')['pdn_type'], 'Non-IP')
        self.assertEqual(decode_paa(b'\x05')['pdn_type'], 'Ethernet')
        for wire in (b'\x00', b'\x06', b'\x81' + v4, b'\x02\x81' + v6, b'\x02\x20' + v6,
                     b'\x01' + v4 + b'\x00', b'\x04\x00'):
            self.assertIsNone(decode_paa(wire))

    def test_fixed_length_payloads_reject_truncation_and_trailing_bytes(self):
        for decoder, wire in ((decode_ambr, bytes(8)), (decode_bearer_qos, QOS),
                              (decode_ebi, b'\x05'), (decode_rat, b'\x06'),
                              (decode_paa, bytes.fromhex('010a789b15'))):
            for size in range(len(wire)):
                self.assertIsNone(decoder(wire[:size]), (decoder.__name__, size))
            self.assertIsNone(decoder(wire + b'\x00'))

    def test_uli_tai_ecgi_values_and_plmn_validation(self):
        result = decode_uli(ULI, self.decoder.decode_plmn)
        self.assertEqual(result['TAI'], {'MCC': '621', 'MNC': '30', 'TAC': '30168', 'raw_hex': '26f10375d8'})
        self.assertEqual(result['ECGI'], {'MCC': '621', 'MNC': '30', 'ECI': '28929363', 'raw_hex': '26f10301b96d53'})
        for data in (ULI[:-1], ULI + b'\x00', b'\x00', b'\x40' + ULI[1:],
                     bytes.fromhex('182ff10375d826f10301b96d53'),
                     bytes.fromhex('1826f10375d826f103f1b96d53')):
            self.assertIsNone(decode_uli(data, self.decoder.decode_plmn))

    def test_uli_all_six_base_fields_in_flag_order(self):
        plmn = bytes.fromhex('130062')  # MCC 310, three-digit MNC 260.
        values = [plmn + bytes.fromhex(x) for x in ('00010002', '00030004', '000506ff', '0007', '00000008', '0009')]
        decoded = decode_uli(b'\x3f' + b''.join(values), self.decoder.decode_plmn)
        self.assertEqual([decoded[k]['MNC'] for k in ('CGI', 'SAI', 'RAI', 'TAI', 'ECGI', 'LAI')], ['260'] * 6)
        self.assertEqual(decoded['CGI']['CellID'], '2')
        self.assertEqual(decoded['SAI']['SAC'], '4')
        self.assertEqual(decoded['RAI']['RAC'], '6')
        self.assertEqual(decoded['LAI']['LAC'], '9')
        self.assertIsNone(decode_uli(b'\x04' + plmn + bytes.fromhex('00050600'), self.decoder.decode_plmn))

    def test_reported_pco_parses_pap_ipcp_and_requests(self):
        result = decode_pco(PCO, 'ue-to-network')
        entries = result['entries']
        self.assertEqual([x['id'] for x in entries], ['0xc023', '0x8021', '0x000d', '0x0005', '0x0010'])
        self.assertEqual(entries[0]['decoded']['code_name'], 'Authenticate-Request')
        self.assertEqual(entries[0]['decoded']['peer_id_raw_hex'], '776562')
        self.assertEqual(entries[0]['decoded']['password_raw_hex'], '776562')
        options = entries[1]['decoded']['options']
        self.assertEqual([o['name'] for o in options], ['primary_dns_server', 'secondary_dns_server'])
        self.assertEqual([o['address'] for o in options], ['0.0.0.0', '0.0.0.0'])
        self.assertTrue(entries[2]['request'])
        self.assertTrue(entries[3]['supported'])
        self.assertTrue(entries[4]['request'])
        self.assertEqual(b'\x80' + b''.join(bytes.fromhex(e['raw_hex']) for e in entries), PCO)

    def test_pco_downlink_values_direction_and_duplicates(self):
        values = entry(13, bytes([8, 8, 8, 8])) + entry(13, bytes([1, 1, 1, 1]))
        values += entry(16, (1500).to_bytes(2, 'big')) + entry(5, b'\x02')
        result = decode_pco(b'\x80' + values, 'network-to-ue')['entries']
        self.assertEqual([r['address'] for r in result[:2]], ['8.8.8.8', '1.1.1.1'])
        self.assertEqual(result[2]['mtu'], 1500)
        self.assertEqual(result[3]['mode_name'], 'MS/NW')
        wrong_direction = decode_pco(b'\x80' + entry(13, b'\x08' * 4), 'ue-to-network')
        self.assertIn('decode_error', wrong_direction['entries'][0])

    def test_pco_ipv6_and_two_octet_container_lengths(self):
        address = ipaddress.IPv6Address('2001:db8::53').packed
        result = decode_pco(b'\x80' + entry(3, address), 'network-to-ue')
        self.assertEqual(result['entries'][0]['address'], '2001:db8::53')
        for direction, kind in (('network-to-ue', 0x23), ('network-to-ue', 0x30), ('ue-to-network', 0x41)):
            value = b'\x80' + entry(kind, b'abc', size_len=2) + entry(0xff01, b'xyz')
            entries = decode_pco(value, direction)['entries']
            self.assertEqual([e['content_raw_hex'] for e in entries], ['616263', '78797a'])
            self.assertTrue(all(e['unsupported'] for e in entries))

    def test_pco_framing_errors_keep_whole_value_raw(self):
        for wire in (b'', b'\x00', b'\x88', b'\x80\x00', b'\x80\x00\x0d',
                     b'\x80\x00\x0d\x04\x00', PCO[:-1], PCO + b'\xff'):
            with self.subTest(wire=wire.hex()):
                self.assertIsNone(decode_pco(wire, 'ue-to-network'))
                result = self.decoder.smart_decode_hex(wire, GTP + 'protConfigOptions.ueToNetwork')
                self.assertEqual(result, 'hex:' + wire.hex())

    def test_pco_bad_inner_packet_does_not_erase_later_entries(self):
        packet = bytes.fromhex('0100000400')  # Declared PPP length does not match.
        result = decode_pco(b'\x80' + entry(0x8021, packet) + entry(0x000d, b''), 'ue-to-network')
        self.assertIn('decode_error', result['entries'][0])
        self.assertTrue(result['entries'][1]['request'])
        self.assertEqual(result['entries'][0]['content_raw_hex'], packet.hex())
        for packet in (bytes.fromhex('010000060000'), bytes.fromhex('0100000881060000')):
            result = decode_pco(b'\x80' + entry(0x8021, packet), 'ue-to-network')
            self.assertIn('decode_error', result['entries'][0])

    def test_pap_ack_unknown_codes_and_malformed_credentials(self):
        ack = bytes.fromhex('02010007024f4b')
        self.assertEqual(decode_pco(b'\x80' + entry(0xc023, ack), 'network-to-ue')['entries'][0]['decoded']['message_raw_hex'], '4f4b')
        unknown = bytes.fromhex('09000004')
        self.assertTrue(decode_pco(b'\x80' + entry(0xc023, unknown), 'network-to-ue')['entries'][0]['decoded']['unsupported'])
        malformed = bytes.fromhex('01000007036162')
        self.assertIn('decode_error', decode_pco(b'\x80' + entry(0xc023, malformed), 'ue-to-network')['entries'][0])

    def test_ip_choice_declared_family_and_invalid_lengths(self):
        for family, address in (('iPV4', '10.209.167.57'), ('iPV6', '2001:db8::1')):
            packed = ipaddress.ip_address(address).packed
            raw = {'iP-type': family, 'iP-value': ('iPBinaryAddress', packed)}
            result = self.decoder.make_json_safe(raw)['iP-value']
            self.assertEqual(result[1]['address'], address)
            self.assertEqual(result[1]['raw_hex'], packed.hex())
            raw['iP-type'] = 'iPV6' if family == 'iPV4' else 'iPV4'
            self.assertEqual(self.decoder.make_json_safe(raw)['iP-value'][1], 'hex:' + packed.hex())
        self.assertEqual(self.decoder.make_json_safe({'iP-value': ('iPBinaryAddress', b'12345')})['iP-value'][1], 'hex:3132333435')

    def test_registry_is_scoped_and_overrides_take_precedence(self):
        with patch.object(ASN1Decoder, 'compile_asn1_from_dir', return_value=None):
            explicit = ASN1Decoder('unused', {'aPN': 'apn-text', GTP + 'rATType': 'hex'})
        self.assertEqual(explicit.smart_decode_hex(b'web.example', 'aPN')['name'], 'web.example')
        self.assertEqual(explicit.smart_decode_hex(b'\x06', GTP + 'rATType'), 'hex:06')
        for path in ('aPN', 'other.aPN', 'ePS-GTPV2-specificParameters.aPNHash', 'other.rATType', 'other.ueToNetwork'):
            self.assertEqual(self.decoder.smart_decode_hex(b'web', path), 'hex:776562')
        self.decoder.use_builtin_formats = False
        self.assertEqual(self.decoder.smart_decode_hex(b'web', GTP + 'aPN'), 'hex:776562')
        self.assertEqual(self.decoder.smart_decode_hex(b'session-1', 'ePSCorrelationNumber'), 'hex:73657373696f6e2d31')

    def test_all_explicit_formats_are_constructor_supported(self):
        with patch.object(ASN1Decoder, 'compile_asn1_from_dir', return_value=None):
            for fmt in [*BYTE_FORMAT_DECODERS, 'gtpv2-uli', 'ip-address']:
                decoder = ASN1Decoder('unused', {'custom': fmt})
                self.assertEqual(decoder.field_formats['custom'], fmt)

    def test_random_payloads_are_bounded_json_safe_and_preserve_raw(self):
        rng = random.Random(9274)
        formats = list(BYTE_FORMAT_DECODERS) + ['gtpv2-uli', 'ip-address']
        for index in range(600):
            wire = bytes(rng.randrange(256) for _ in range(rng.randrange(48)))
            fmt = formats[index % len(formats)]
            self.decoder.field_formats = {'test': fmt}
            result = self.decoder.smart_decode_hex(wire, 'test')
            orjson.dumps(result)
            self.assertEqual(result['raw_hex'] if isinstance(result, dict) else result[4:], wire.hex())

    def test_eps_fields_through_ber_and_der(self):
        schema = '''Example DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            Records ::= SEQUENCE OF CHOICE { iRI-Begin-record Record }
            Record ::= SEQUENCE {
                ePSCorrelationNumber OCTET STRING,
                networkIdentifier SEQUENCE { network-Element-Identifier CHOICE { iP-Address SEQUENCE {
                    iP-type ENUMERATED { iPV4(0), iPV6(1) },
                    iP-value CHOICE { iPBinaryAddress OCTET STRING } } } },
                ePS-GTPV2-specificParameters SEQUENCE {
                    aPN OCTET STRING, aPN-AMBR OCTET STRING, ePSBearerIdentity OCTET STRING,
                    ePSBearerQoS OCTET STRING, rATType OCTET STRING, pDNAddressAllocation OCTET STRING,
                    ePSlocationOfTheTarget SEQUENCE { userLocationInfo OCTET STRING },
                    protConfigOptions SEQUENCE { ueToNetwork OCTET STRING }
                }
            }
            END'''
        record = {'networkIdentifier': {'network-Element-Identifier': ('iP-Address', {
            'iP-type': 'iPV4', 'iP-value': ('iPBinaryAddress', bytes.fromhex('0ad1a739'))})},
            'ePS-GTPV2-specificParameters': {'aPN': b'web.example.net', 'aPN-AMBR': bytes.fromhex('0040000000400000'),
                'ePSBearerIdentity': b'\x05', 'ePSBearerQoS': QOS, 'rATType': b'\x06',
                'pDNAddressAllocation': bytes.fromhex('010a789b15'),
                'ePSlocationOfTheTarget': {'userLocationInfo': ULI}, 'protConfigOptions': {'ueToNetwork': PCO}}}
        values = [('iRI-Begin-record', dict(record, ePSCorrelationNumber=correlation))
                  for correlation in (b'session-1', bytes.fromhex('7974863829dc4381'))]
        for encoding in ('ber', 'der'):
            self.decoder.spec = asn1tools.compile_string(schema, encoding)
            wire = self.decoder.spec.encode('Records', values)
            accepted, result = self.decoder.process_bytes(wire, roots='Records')
            self.assertTrue(accepted, result)
            records = [v[1] for v in result['content']]
            self.assertEqual([r['ePSCorrelationNumber'] for r in records], ['session-1', 'hex:7974863829dc4381'])
            for record in records:
                params = record['ePS-GTPV2-specificParameters']
                self.assertEqual(params['aPN']['name'], 'web.example.net')
                self.assertEqual(params['aPN-AMBR']['uplink_kbps'], 4194304)
                self.assertEqual(params['ePSBearerIdentity']['value'], 5)
                self.assertEqual(params['ePSBearerQoS']['qci'], 9)
                self.assertEqual(params['rATType']['name'], 'EUTRAN')
                self.assertEqual(params['pDNAddressAllocation']['ipv4_address'], '10.120.155.21')
                self.assertEqual(params['ePSlocationOfTheTarget']['userLocationInfo']['ECGI']['ECI'], '28929363')
                self.assertEqual(len(params['protConfigOptions']['ueToNetwork']['entries']), 5)
                self.assertEqual(record['networkIdentifier']['network-Element-Identifier'][1]['iP-value'][1]['address'], '10.209.167.57')
            self.assertEqual(orjson.loads(orjson.dumps(result)), result)


if __name__ == '__main__':
    unittest.main()
