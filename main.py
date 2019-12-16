import Program
import SocketAPI


if __name__ == '__main__':
    sock = SocketAPI.SocketAPI()
    program = Program.Program(sock)
    program.run()

