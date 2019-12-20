import unittest
import PcapWriter


class FakeFile:
    def __init__(self):
        self.data = []

    def close(self):
        pass

    def write(self, data):
        self.data.append(data)


class TestPcapWriter(unittest.TestCase):
    GLOBAL_HEADER = (b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00')
    def test_create_global_header(self):
        header = PcapWriter.PcapWriter.create_global_header()
        self.assertEqual(header, TestPcapWriter.GLOBAL_HEADER, 'Wrong global header')

    def test_create_packet_header(self):
        packet = b'\x00\x00\x00\x00'
        time = (1, 20)
        header = PcapWriter.PcapWriter.create_pcap_header(packet, time)
        expected = b'\x01\x00\x00\x00\x14\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00'
        self.assertEqual(header, expected, 'Wrong packet header')

    def test_write_to_file(self):
        packet = b'\x00\x00\x00\x00'
        time = (1, 20)
        file = FakeFile()
        writer = PcapWriter.PcapWriter()
        writer.open(file)
        writer.write_packet(packet, time)

        self.assertEqual(file.data[0], TestPcapWriter.GLOBAL_HEADER, 'Wrong global header')
        self.assertEqual(
            file.data[1], b'\x01\x00\x00\x00\x14\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00',
            'Wrong packet header')
        self.assertEqual(file.data[2], b'\x00\x00\x00\x00', 'Wrong file data')