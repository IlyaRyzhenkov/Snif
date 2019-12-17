import Parser


class Program:
    def __init__(self, sock):
        self.sock = sock

    def run(self):
        self.sock.create()
        while True:
            data = self.sock.recv_data()
            eth_data = Parser.ProtoParser.parse_eth(data[0])
            if eth_data.proto == 2048:
                ip_data = Parser.ProtoParser.parse_ip4(eth_data.data)
                print(f'Source:{self.ip_to_string(ip_data.source_ip)},',
                      f'Dest:{self.ip_to_string(ip_data.dest_ip)}')
            print('Not ip packet')

    @staticmethod
    def ip_to_string(ip):
        return f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}'
