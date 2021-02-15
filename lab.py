from argparse import ArgumentParser, ArgumentTypeError
from sys import stderr
from code import InteractiveConsole
from readline import set_completer, parse_and_bind
from rlcompleter import Completer

from scapy.all import *

def pkt_callback(pkt):
    pass

def main(args):

    if args.filter:
        pkt_filter = ' '.join(args.filter)
    else:
        pkt_filter = None

    pkts = sniff(iface=args.iface, filter=pkt_filter, count=args.count, prn=pkt_callback)

    if args.interact:
        vars = globals()
        vars.update(locals())

        set_completer(Completer(vars).complete)
        parse_and_bind("tab: complete")

        InteractiveConsole(vars).interact()

if __name__ == '__main__':

    def count_type(count):
        count = int(count)

        if count == 0:
            print(f'{__file__}: ignoring packet count argument', file=stderr)
        elif count < 0:
            raise ArgumentTypeError('COUNT must be a positive integer')

        return count

    parser = ArgumentParser()

    parser.add_argument('iface', help='name of network interface to capture packets from')
    parser.add_argument('-c', '--count', type=count_type, default=0)
    parser.add_argument('-f', '--filter', nargs='*')
    parser.add_argument('-i', '--interact', action='store_true')

    args = parser.parse_args()

    main(args)
