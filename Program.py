import Parser


class Program:
    def __init__(self, filter, writer, timer, sock):
        self.sock = sock
        self.filter = filter
        self.timer = timer
        self.writer = writer
        self.host = sock.get_host()

    def run(self):
        self.sock.create()
        while True:
            data = self.sock.recv_data()
            time = self.timer.get_time()
            self.writer.write_packet(data[0], time)
            parsed = Parser.ParsedPacket(data[0])
            if self.filter.filter(parsed):
                if parsed.is_ip:
                    if parsed.ip_data.source_ip == self.host:
                        print(f'Send to {parsed.ip_data.dest_ip}      {len(data[0])} bytes')
                    else:
                        print(f'Received from {parsed.ip_data.source_ip}     {len(data[0])} bytes')

