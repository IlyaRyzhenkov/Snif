import enum
import itertools
import socket
import sys
import Program


class Filter:
    def __init__(self, args):
        self.dest_ip = set()
        self.source_ip = set()
        self.dest_port = set()
        self.source_port = set()

        place = Place.BOTH
        level = None
        ip = None
        port = None
        print(args)
        for arg in itertools.chain.from_iterable(args):
            item = Filter.get_item_by_arg(arg)
            if isinstance(item, Place):
                place = item
                continue
            if isinstance(item, Level):
                level = item
                continue

            if item == Command.ADD:
                if ip and not port:
                    if place == Place.DEST:
                        self.dest_ip.add(ip)
                    elif place == Place.SOURCE:
                        self.source_ip.add(ip)
                    else:
                        self.source_ip.add(ip)
                        self.dest_ip.add(ip)

                if ip and port:
                    if place == Place.DEST:
                        self.dest_port.add((ip, port))
                    elif place == Place.SOURCE:
                        self.source_port.add((ip, port))
                    else:
                        self.source_port.add((ip, port))
                        self.dest_port.add((ip, port))
                continue

            if level == Level.IP:
                ip = Filter.get_ip(arg)

            if level == level.PORT:
                port = Filter.get_port(arg)
        print(self.dest_ip)

    def filter(self, packet):
        if packet.is_ip:
            if Program.Program.ip_to_string(packet.ip_data.source_ip) in self.source_ip or Program.Program.ip_to_string(packet.ip_data.dest_ip) in self.dest_ip:
                return True
        return False

    @staticmethod
    def get_item_by_arg(arg):
        arg = arg.lower()
        if arg == 'dest':
            return Place.DEST
        if arg == 'source':
            return Place.SOURCE
        if arg == 'both':
            return Place.BOTH
        if arg == 'ip':
            return Level.IP
        if arg == 'port' or arg == ':':
            return Level.PORT
        if arg == 'add':
            return Command.ADD
        return arg

    @staticmethod
    def get_ip(addr):
        try:
            return socket.gethostbyname(addr)
        except OSError as e:
            sys.stderr.write(f'Wrong address {addr}')
            return None

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


class Place(enum.Enum):
    BOTH = 0
    SOURCE = 1
    DEST = 2


class Level(enum.Enum):
    IP = 1
    PORT = 2


class Command(enum.Enum):
    ADD = 1
