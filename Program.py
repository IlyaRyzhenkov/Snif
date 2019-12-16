class Program:
    def __init__(self, sock):
        self.sock = sock

    def run(self):
        self.sock.create()
        while True:
            data = self.sock.recv_data()
            self.parse_packet(data)

    @staticmethod
    def parse_packet(data):
        if data[1][1] != 2048:
            print('Not ipv4 packet')
            return
        eth = data[0][0:14]
        ip = data[0][14:34]
        source_ip = f'{ip[12]}.{ip[13]}.{ip[14]}.{ip[15]}'
        dest_ip = f'{ip[16]}.{ip[17]}.{ip[18]}.{ip[19]}'
        print(f'Sourse:{source_ip} Dest:{dest_ip}')

