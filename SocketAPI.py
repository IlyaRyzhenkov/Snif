import socket
import sys


class SocketAPI:
    def __init__(self, interface=''):
        self.interface = interface
        self.sock = None
        self.mtu = 1500

    def create(self):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if self.interface:
            try:
                self.sock.bind((self.interface, 0))
            except OSError as e:
                sys.stderr.write(f'Error with interface {self.interface}')
                sys.stderr.write(e)
                sys.exit(2)

    def recv_data(self):
        data = self.sock.recvfrom(self.mtu)
        return data
