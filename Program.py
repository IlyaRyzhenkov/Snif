import Parser, Timer, Visualiser


class Program:
    def __init__(self, filter, writer, sock, timer=Timer.Timer(), visualiser=Visualiser.Visualiser()):
        self.sock = sock
        self.filter = filter
        self.timer = timer
        self.visualiser = visualiser
        self.writer = writer

    def run(self):
        self.sock.create()
        self.timer.update_timer()
        while True:
            data = self.sock.recv_data()
            time = self.timer.get_time()
            delta = self.timer.get_time_delta()
            self.writer.write_packet(data[0], time)
            parsed = Parser.ParsedPacket(data[0])
            if self.filter.filter(parsed):
                self.visualiser.print_packet(parsed, delta)
