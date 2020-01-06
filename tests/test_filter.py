import unittest
import Filter
import Parser


class TestFilter(unittest.TestCase):
    def test_rule_creation(self):
        args = ['s_ip', '1.1.1.1', 'd_ip', '2.2.2.2', 's_port', '8080', 'd_port', '4040']
        rule = Filter.Rule(args)
        self.assertEqual(rule.source_ip, '1.1.1.1', 'Wrong source ip')
        self.assertEqual(rule.dest_ip, '2.2.2.2', 'Wrong dest ip')
        self.assertEqual(rule.source_port, 8080, 'Wrong source port')
        self.assertEqual(rule.dest_port, 4040, 'Wrong dest port')

    def test_get_port(self):
        expected = 8080
        actual = Filter.Filter.get_port('8080')
        self.assertEqual(actual, expected, 'Wrong port')

    def test_rule_filter(self):
        data = (b"\x10\xf0\x05\x99\x20\xeb\x10\xfe\xed\x6e\x20\x52\x08\x00"
                b"\x45\x00\x00\x28\x1f\xbc\x40\x00\x3a\x06\xec\xfc\x68\x1a"
                b"\x0a\xf0\xc0\xa8\x00\x65\x01\xbb\xc4\x97\xf1\x85\x68\x1a"
                b"\x51\x36\x23\x89\x50\x10\x00\x21\xe6\xe9\x00\x00\x00\x00")
        packet = Parser.ParsedPacket(data)
        args = ['s_ip', '104.26.10.240', 'd_ip', '192.168.0.101', 's_port', '443', 'd_port', '50327']
        rule = Filter.Rule(args)
        self.assertTrue(rule.filter(packet))

    def test_rule_not_filter(self):
        data = (b"\x10\xf0\x05\x99\x20\xeb\x10\xfe\xed\x6e\x20\x52\x08\x00"
                b"\x45\x00\x00\x28\x1f\xbc\x40\x00\x3a\x06\xec\xfc\x68\x1a"
                b"\x0a\xf0\xc0\xa9\x00\x65\x01\xbb\xc4\x97\xf1\x85\x68\x1a"
                b"\x51\x36\x23\x89\x50\x10\x00\x21\xe6\xe9\x00\x00\x00\x00")
        packet = Parser.ParsedPacket(data)
        args = ['s_ip', '104.26.10.240', 'd_ip', '192.168.0.101', 's_port', '443', 'd_port', '50327']
        rule = Filter.Rule(args)
        self.assertFalse(rule.filter(packet))

    def test_filter(self):
        data = (b"\x10\xf0\x05\x99\x20\xeb\x10\xfe\xed\x6e\x20\x52\x08\x00"
                b"\x45\x00\x00\x28\x1f\xbc\x40\x00\x3a\x06\xec\xfc\x68\x1a"
                b"\x0a\xf0\xc0\xa8\x00\x65\x01\xbb\xc4\x97\xf1\x85\x68\x1a"
                b"\x51\x36\x23\x89\x50\x10\x00\x21\xe6\xe9\x00\x00\x00\x00")
        packet = Parser.ParsedPacket(data)
        args = [['s_ip', '104.26.10.240', 'd_ip', '192.168.0.101', 's_port', '443', 'd_port', '50327']]
        filter = Filter.Filter(args)
        self.assertTrue(filter.filter(packet))
