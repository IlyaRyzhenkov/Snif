class Program:
    def __init__(self, sock, out):
        self.sock = sock
        self.out = out

    def run(self):
        while True:
            data = self.sock.recv_data()
            self.out.send_data(data)
