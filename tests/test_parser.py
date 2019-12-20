import unittest
import Parser


class TestParser(unittest.TestCase):
    def test_parse_eth(self):
        packet = (b'\x01\x02\x03\x04\x05\x06\x0a\x0b\x0c\x0d'
                  b'\x0e\x0f\x08\x00\x22\x33\x44')
        data = Parser.ProtoParser.parse_eth(packet)
        self.assertEqual(data.dest_mac, (1, 2, 3, 4, 5, 6),
                         'Wrong dest mac address')
        self.assertEqual(data.source_mac, (10, 11, 12, 13, 14, 15),
                         'Wrong source address')
        self.assertEqual(data.proto, 2048, 'Wrong proto number')
        self.assertEqual(data.data, b'\x22\x33\x44',
                         'Wrong next level data')

    def test_parse_ip4(self):
        packet = (b"\x45\x00\x00\x28\x1f\xbc\x40\x00\x3a\x06\xec\xfc"
                  b"\x68\x1a\x0a\xf0\xc0\xa8\x00\x65\x01\xbb\xc4")
        data = Parser.ProtoParser.parse_ip4(packet)
        self.assertEqual(data.version, 4, 'Wrong version')
        self.assertEqual(data.header_length, 5, 'Wrong header length')
        self.assertEqual(data.service, 0, 'Wrong service')
        self.assertEqual(data.packet_length, 40, 'Wrong total length')
        self.assertEqual(data.id, 8124, 'Wrong id')
        self.assertEqual(data.flags, 2, 'Wrong flags')
        self.assertEqual(data.ttl, 58, 'Wrong ttl')
        self.assertEqual(data.proto, 6, 'Wrong proto')
        self.assertEqual(data.dest_ip, '192.168.0.101', 'Wrong dest ip')
        self.assertEqual(data.source_ip, '104.26.10.240', 'Wrong source ip')
        self.assertEqual(data.data, b'\x01\xbb\xc4', 'Wrong data')
        self.assertIsNone(data.parameters, 'Wrong parameters')

    def test_parse_tcp(self):
        packet = (b"\x01\xbb\xc4\x97\xf1\x85\x68\x1a\x51\x36\x23\x89"
                  b"\x50\x10\x00\x21\xe6\xe9\x00\x00\x00\x00")
        data = Parser.ProtoParser.parse_tcp(packet)
        self.assertEqual(data.source_port, 443, 'Wrong source port')
        self.assertEqual(data.dest_port, 50327, 'Wrong dest port')
        self.assertEqual(data.seq, 4052051994, 'Wrong sequence number')
        self.assertEqual(data.ack, 1362502537, 'Wrong ack number')
        self.assertEqual(data.header_length, 5, 'Wrong header length')
        self.assertEqual(data.flags, 5, 'Wrong flags')
        self.assertEqual(data.window_size, 33, 'Wrong window size')
        self.assertEqual(data.urgent_pointer, 0, 'Wrong urgent poiner')
        self.assertIsNone(data.options, 'Wrong options')
        self.assertEqual(data.data, b'\x00\x00', 'Wrong data')

    def test_parse_udp(self):
        packet = b'\x00\x01\x00\x10\x00\x0a\xaa\xaa\x00\x00'
        data = Parser.ProtoParser.parse_udp(packet)
        self.assertEqual(data.source_port, 1, 'Wrong source port')
        self.assertEqual(data.dest_port, 16, 'Wrong dest port')
        self.assertEqual(data.length, 10, 'Wrong length')
        self.assertEqual(data.data, b'\x00\x00', 'Wrong data')

    def test_get_ip(self):
        ip = 3232235621
        res = Parser.ProtoParser.get_ip_from_int(ip)
        self.assertEqual(res, '192.168.0.101', 'Wrong ip')

    def test_parse_tcp_packet(self):
        packet = (b"\x10\xf0\x05\x99\x20\xeb\x10\xfe\xed\x6e\x20\x52\x08\x00"
                  b"\x45\x00\x00\x28\x1f\xbc\x40\x00\x3a\x06\xec\xfc\x68\x1a"
                  b"\x0a\xf0\xc0\xa8\x00\x65\x01\xbb\xc4\x97\xf1\x85\x68\x1a"
                  b"\x51\x36\x23\x89\x50\x10\x00\x21\xe6\xe9\x00\x00\x00\x00")
        parsed_packet = Parser.ParsedPacket(packet)
        self.assertTrue(parsed_packet.is_ip, 'Wrong IP flag')
        self.assertTrue(parsed_packet.is_tcp, 'Wrong TCP flag')
        self.assertFalse(parsed_packet.is_udp, 'Wrong UDP flag')
        self.assertEqual(parsed_packet.inner_data, b'\x00\x00', 'Wrong inner data')
