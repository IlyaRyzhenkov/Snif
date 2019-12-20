import struct


class ProtoParser:
    @staticmethod
    def parse_eth(data):
        dest_mac = struct.unpack('BBBBBB', data[0:6])
        source_mac = struct.unpack('BBBBBB', data[6:12])
        next_proto = struct.unpack('>H', data[12:14])[0]
        next_level_data = data[14:]
        return EthData(dest_mac, source_mac, next_proto, next_level_data)

    @staticmethod
    def parse_ip4(data):
        version_length, type_of_serv, packet_length, packet_id,\
        flags_ofset, ttl, next_proto, checksum, source_ip,\
        dest_ip = struct.unpack('>BBHHHBBHII', data[0:20])
        version = version_length & 0b11110000
        header_length = version_length & 0b1111
        flags = flags_ofset & 0b1110000000000000
        ofset = flags_ofset & 0b0001111111111111
        parameters = data[20:header_length*4]
        next_level_data = data[header_length*4:]
        return IpData(version, header_length, type_of_serv, packet_length,
                      packet_id, flags, ofset, ttl, next_proto, checksum,
                      ProtoParser.get_ip_from_int(dest_ip),
                      ProtoParser.get_ip_from_int(source_ip), parameters,
                      next_level_data)

    @staticmethod
    def get_ip_from_int(num):
        ip3 = num & 0b11111111
        ip2 = (num > 8) & 0b11111111
        ip1 = (num > 16) & 0b11111111
        ip0 = (num > 24) & 0b11111111
        return ip0, ip1, ip2, ip3


class EthData:
    def __init__(self, dest_mac, source_mac, proto, next_level_data):
        self.dest_mac = dest_mac
        self.source_mac = source_mac
        self.proto = proto
        self.data = next_level_data


class IpData:
    def __init__(self, version, header_length, service, packet_length,
                 id, flags, ofset, ttl, next_proto, checksum, dest_ip,
                 source_ip, parameters, next_level_data):
        self.version = version
        self.header_length = header_length
        self.service = service
        self.packet_length = packet_length
        self.id = id
        self.flags = flags
        self.ofset = ofset
        self.ttl = ttl
        self.proto = next_proto
        self.checksum = checksum
        self.dest_ip = dest_ip
        self.source_ip = source_ip
        if parameters:
            self.parameters = parameters
        else:
            self.parameters = None
        self.data = next_level_data
