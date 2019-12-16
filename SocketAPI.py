import socket


class SocketAPI:
    def __init__(self):
        self.sock = None
        self.mtu = 1500

    def create(self):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL))

    def recv_data(self):
        data = self.sock.recvfrom(self.mtu)