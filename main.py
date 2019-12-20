import sys
import Program
import SocketAPI
import argparse
import Filter
import PcapWriter


def parse_arguments():
    arg_parser = argparse.ArgumentParser(
        description='Web sniffer for linux (pcap format)')
    arg_parser.add_argument(
        '-i', '--interface', help='Use this network interface to capture packets')
    arg_parser.add_argument(
        '-f', '--filter', action='append',
        help=('Use filter for displaying:\n'
              '-f [source/dest/both] ip [ip1 add, ip2 add, ...] to filter by ip\n'
              '-f [source/dest/both] port [port1 add, port2 add, ...] to filter by port\n'
              'if [source/dest/both] is not specified, default is both'))
    arg_parser.add_argument('-F', '--File', type=argparse.FileType('wb'))
    res = arg_parser.parse_args()
    return res


if __name__ == '__main__':
    if sys.platform == 'win32':
        sys.stderr.write('Windows don\'t supported\n')
        sys.exit(1)
    parsed = parse_arguments()
    filter = Filter.Filter(parsed.filter)
    if parsed.interface:
        sock = SocketAPI.SocketAPI(parsed.interface)
    else:
        sock = SocketAPI.SocketAPI()
    writer = PcapWriter.PcapWriter()
    if parsed.File:
        writer.open(parsed.File)
    program = Program.Program(filter, writer, sock)

    try:
        program.run()
    finally:
        writer.close()
