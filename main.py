import sys
import Program
import SocketAPI
import argparse
import Filter
import PcapWriter
import Timer


def parse_arguments():
    arg_parser = argparse.ArgumentParser(
        description='Web sniffer for linux (pcap format)')
    arg_parser.add_argument(
        '-i', '--interface', help='Use this network interface to capture packets')
    arg_parser.add_argument(
        '-f', '--filter', action='append', nargs='+', metavar='RULE String',
        help=('Use filter for displaying:\n'
              '-f [s_ip ip] [d_ip ip] [s_port port] [d_port port] adds filter rule'))
    arg_parser.add_argument('-F', '--File', type=argparse.FileType('wb'))
    res = arg_parser.parse_args()
    return res


if __name__ == '__main__':
    if sys.platform == 'win32':
        sys.stderr.write('Windows don\'t supported\n')
        sys.exit(1)
    parsed = parse_arguments()
    if parsed.filter:
        filter = Filter.Filter(parsed.filter)
    else:
        filter = Filter.Filter([])
    if parsed.interface:
        sock = SocketAPI.SocketAPI(parsed.interface)
    else:
        sock = SocketAPI.SocketAPI()
    writer = PcapWriter.PcapWriter()
    if parsed.File:
        writer.open(parsed.File)
    timer = Timer.Timer()

    program = Program.Program(filter, writer, timer, sock)

    try:
        program.run()
    finally:
        writer.close()
