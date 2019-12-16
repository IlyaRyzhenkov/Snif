import sys
import Program
import SocketAPI


if __name__ == '__main__':
    if sys.platform == 'win32':
        sys.stderr.write('Windows don\'t supported')
        exit(1)

    sock = SocketAPI.SocketAPI()
    program = Program.Program(sock)
    program.run()
