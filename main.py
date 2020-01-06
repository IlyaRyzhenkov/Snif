import sys
import Program
import SocketAPI
import argparse
import Filter
import PcapWriter
import Timer
import Statistics


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
    arg_parser.add_argument(
        '-s', '--statistics', metavar='stat arg', nargs='+', action='append',
        help='Use to set additional stat properties')
    arg_parser.add_argument('-t', '--time', type=check_positive_float,
        help='Set time interval for statistics')
    res = arg_parser.parse_args()
    return res


def check_positive_float(value):
    res = float(value)
    if res < 0:
        raise argparse.ArgumentTypeError('Value should be positive float value')
    return res


if __name__ == '__main__':
    if sys.platform == 'win32':
        sys.stderr.write('Windows don\'t supported\n')
        sys.exit(1)
    parsed = parse_arguments()

    host = SocketAPI.SocketAPI.get_host()

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

    if parsed.statistics:
        stat = Statistics.GroupIPStatManager(parsed.statistics, host)
    else:
        stat = Statistics.GroupIPStatManager([], host)

    if parsed.time:
        interval_timer = Timer.IntervalTimer(parsed.time, stat)
        interval_timer.start()

    program = Program.Program(filter, writer, sock, host=host, additional_stat=stat)
    try:
        program.run()
    except KeyboardInterrupt as e:
        print(program.general_stat.get_stat_str())
        print(program.stat.get_stat_str())
    finally:
        writer.close()
