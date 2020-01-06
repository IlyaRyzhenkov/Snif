import Parser
import Timer
import Visualiser
import Statistics


class Program:
    def __init__(
            self, filter, writer, sock, timer=Timer.Timer(),
            visualiser=Visualiser.Visualiser(), host='0.0.0.0',
            additional_stat=Statistics.GroupIPStatManager([], '0.0.0.0')):
        self.sock = sock
        self.filter = filter
        self.timer = timer
        self.visualiser = visualiser
        self.writer = writer
        self.host = sock.get_host()
        self.general_stat = Statistics.GeneralStatistics(host)
        self.stat = additional_stat

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
            self.general_stat.update(parsed)
            self.stat.update(parsed)
