import socket


class SocketAPI:
    def __init__(self):
        self.sock = None
        self.mtu = 1500

    def create(self):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    def recv_data(self):
        data = self.sock.recvfrom(self.mtu)
        return data

