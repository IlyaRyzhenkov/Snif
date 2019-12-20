import Parser


class Program:
    def __init__(self, filter, writer, timer, sock):
        self.sock = sock
        self.filter = filter
        self.timer = timer
        self.writer = writer

    def run(self):
        self.sock.create()
        while True:
            data = self.sock.recv_data()
            time = self.timer.get_time()
            self.writer.write_packet(data[0], time)
            parsed = Parser.ParsedPacket(data[0])
            if self.filter.filter(parsed):
                print(f'Source:{self.ip_to_string(parsed.ip_data.source_ip)},',
                      f'Dest:{self.ip_to_string(parsed.ip_data.dest_ip)}')

    @staticmethod
    def ip_to_string(ip):
        return f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}'
