import SocketAPI
import sys


class Filter:
    def __init__(self, args):
        self.rules = []
        for arg_list in args:
            self.rules.append(Rule(arg_list))

    def filter(self, packet):
        if not self.rules:
            return True
        return any((rule.filter(packet) for rule in self.rules))

    @staticmethod
    def get_port(num):
        try:
            port = int(num)
            if 65536 <= port < 0:
                raise ValueError
            return port
        except ValueError:
            sys.stderr.write(f'Wrong port {num}')
            return None


class Rule:
    def __init__(self, args):
        self.source_ip = None
        self.dest_ip = None
        self.source_port = None
        self.dest_port = None

        for i in range(0, len(args), 2):
            try:
                if args[i] == 's_ip':
                    self.source_ip = SocketAPI.SocketAPI.get_ip(args[i+1])
                elif args[i] == 'd_ip':
                    self.dest_ip = SocketAPI.SocketAPI.get_ip(args[i+1])
                elif args[i] == 's_port':
                    self.source_port = Filter.get_port(args[i+1])
                elif args[i] == 'd_port':
                    self.dest_port = Filter.get_port(args[i+1])
                else:
                    raise ValueError
            except Exception as e:
                sys.stderr.write('Error while parsing filter args', e, sep='\n')

    def filter(self, packet):
        if not packet.is_ip:
            return False
        if self.source_ip:
            if packet.ip_data.source_ip != self.source_ip:
                return False
        if self.dest_ip:
            if packet.ip_data.dest_ip != self.dest_ip:
                return False
        if self.dest_port or self.source_port:
            if not (packet.is_tcp or packet.is_udp):
                return False
        if self.source_port:
            if packet.tcp_data.source_port != self.source_port:
                return False
        if self.dest_port:
            if packet.tcp_data.dest_port != self.dest_port:
                return False
        return True
