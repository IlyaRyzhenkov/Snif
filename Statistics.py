import collections
import sys


class GeneralStatistics:
    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.recv_packets = 0
        self.recv_bytes = 0
        self.send_packets = 0
        self.send_bytes = 0
        self.not_ip_packets = 0
        self.not_ip_bytes = 0

    def update(self, packet):
        if not packet.is_ip:
            self.not_ip_packets += 1
            self.not_ip_bytes += packet.length
            return

        if packet.ip_data.source_ip == self.host_ip:
            self.send_packets += 1
            self.send_bytes += packet.length
        else:
            self.recv_packets += 1
            self.recv_bytes += packet.length

    def get_stat_str(self):
        return (f'Received ip packets:{self.recv_packets}, total {self.recv_bytes} '
                f'bytes.\nSend ip packets:{self.send_packets}, total {self.send_bytes} '
                f'bytes.\nNon ip packets:{self.not_ip_packets}, total {self.not_ip_bytes} '
                f'bytes\n')


class GroupIPStatManager:
    def __init__(self, args, host_ip):
        self.stats = []

        for arg in args:
            try:
                port_pos = self.find_port(arg)
                ip = arg[0:port_pos]
                port = arg[port_pos + 1:]
                self.stats.append(GroupIPStat(host_ip, ip, port))
            except Exception as e:
                sys.stderr.write(f'Error parsing stat args:{arg}\n')

    def update(self, packet):
        for stat in self.stats:
            stat.update(packet)

    def pack_measure(self):
        for stat in self.stats:
            stat.pack_measure()

    def get_values(self):
        values = []
        for stat in self.stats:
            values.append(stat.get_value())
        return values

    def get_stat_str(self):
        res = ''
        for stat in self.stats:
            res += stat.get_stat_str()
        return res

    @staticmethod
    def find_port(args_list):
        if 'port' in args_list:
            return args_list.index('port')
        return len(args_list)


class GroupIPStat:
    MEASURE = collections.namedtuple('Measure', ['send_packets', 'send_bytes', 'recv_packets', 'recv_bytes'])

    def __init__(self, host_ip, ip_settings, port_settings):
        self.host_ip = host_ip
        self.recv_packets = 0
        self.recv_bytes = 0
        self.send_packets = 0
        self.send_bytes = 0

        self.measures = []

        ip1 = self.get_ip_as_int(ip_settings[0])
        self.smin_ip = ip_settings[0]
        if len(ip_settings == 2):
            ip2 = self.get_ip_as_int(ip_settings[1])
            self.smax_ip = ip_settings[1]
        else:
            ip2 = ip1
            self.smax_ip = self.smin_ip

        if ip2 < ip1:
            ip1, ip2 = ip2, ip1

        self.min_ip = ip1
        self.max_ip = ip2
        self.has_port_filter = False

        if port_settings:
            self.has_port_filter = True
            min_port = int(port_settings[0])
            if len(port_settings) == 2:
                max_port = int(port_settings[1])
            else:
                max_port = min_port

            if max_port < min_port:
                min_port, max_port = max_port, min_port
            self.min_port = min_port
            self.max_port = max_port

    @staticmethod
    def get_ip_as_int(ip):
        res = 0
        for num in map(int, ip.split('.')):
            res = res * 256 + num
        return res

    def update(self, packet):
        if not packet.is_ip:
            return
        if self.min_ip <= self.get_ip_as_int(packet.ip_data.source_ip) <= self.max_ip:
            if self.has_port_filter:
                if packet.is_tcp:
                    if self.min_port <= packet.tcp_data.source_port <= self.max_port:
                        self.update_measure(packet)
                    return
                if packet.is_udp:
                    if self.min_port <= packet.udp_data.source_port <= self.max_port:
                        self.update_measure(packet)
                    return
                return
            self.update_measure(packet)
            return

        if self.min_ip <= self.get_ip_as_int(packet.ip_data.dest_ip) <= self.max_ip:
            if self.has_port_filter:
                if packet.is_tcp:
                    if self.min_port <= packet.tcp_data.dest_port <= self.max_port:
                        self.update_measure(packet)
                    return
                if packet.is_udp:
                    if self.min_port <= packet.udp_data.dest_port <= self.max_port:
                        self.update_measure(packet)
                    return
                return
            self.update_measure(packet)

    def update_measure(self, packet):
        if packet.ip_data.source_ip == self.host_ip:
            self.send_packets += 1
            self.send_bytes += packet.length
        else:
            self.recv_packets += 1
            self.recv_bytes += packet.length

    def pack_measure(self):
        self.measures.append(self.MEASURE(
            self.send_packets, self.send_bytes, self.recv_packets, self.recv_bytes))
        self.send_packets = 0
        self.send_bytes = 0
        self.recv_packets = 0
        self.recv_bytes = 0

    def get_value(self):
        if self.has_port_filter:
            return (self.smin_ip, self.smax_ip, self.min_port, self.max_port), self.measures
        return (self.smin_ip, self.smax_ip), self.measures

    def get_stat_str(self):
        res = ''
        if self.has_port_filter:
            res += (f'Ip from {self.smin_ip} to {self.smax_ip}, '
                    f'port from {self.min_port} to {self.max_port}:\n')
        else:
            res += f'Ip from {self.smin_ip} to {self.smax_ip}:\n'
        for measure in self.measures:
            res += (f'{measure.send_packets} packets send, total '
                    f'{measure.send_bytes} bytes\n{measure.recv_packets} '
                    f'packets received, total {measure.recv_bytes} bytes\n\n')
        return res
