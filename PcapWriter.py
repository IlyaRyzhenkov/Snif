import struct


class PcapWriter:
    def __init__(self):
        self.file = None

    def open(self, file):
        self.file = file
        self.file.write(PcapWriter.create_global_header())

    def close(self):
        if self.file:
            self.file.close()

    def write_packet(self, packet, time):
        header = PcapWriter.create_pcap_header(packet, time)
        self.file.write(header)
        self.file.write(packet)
        self.file.write(header)

    @staticmethod
    def create_pcap_header(packet, time):
        timestamp_seconds, timestamp_microseconds = time
        length = len(packet)
        return struct.pack(
            '>IIII', timestamp_seconds,timestamp_microseconds, length, length)

    @staticmethod
    def create_global_header():
        magic = b'\xA1\xB2\xC3\xD4'
        version1 = b'\x00\x00\x00\x02'
        version2 = b'\x00\x00\x00\x04'
        zone = b'\x00\x00\x00\x00'
        sigfigs  = b'\x00\x00\x00\x00'
        snaplen = b'\x00\x01\x00\x00'
        network = b'\x00\x00\x00\x01'
        return magic + version1 + version2 + zone + sigfigs + snaplen + network
