import argparse
import logging
from traceroute import find_route


def parse_arguments():
    arg_parser = argparse.ArgumentParser('Traceroute')
    arg_parser.add_argument('ip_address', type=str,
                            help='ip address for tracking')
    arg_parser.add_argument('protocol', type=str,
                            help='protocol for traceroute')
    arg_parser.add_argument('-t', '--timeout', type=float, default=2,
                            required=False,
                            help='response timeout (2 seconds by default)')
    arg_parser.add_argument('-p', '--port', type=int, required=False,
                            help='port (for tcp or udp)')
    arg_parser.add_argument('-v', action='store_true',
                            help='output of the autonomous system number for each ip address')
    arg_parser.add_argument('-n', '--max-ttl', type=int, default=64, required=False, help='')
    arg_parser.add_argument('--max-req', type=int, default=3, required=False,
                            help='')
    arg_parser.add_argument('-6', '--ipv6', action='store_true', help='')

    return arg_parser.parse_args()


def main():
    args = parse_arguments()
    if args.protocol not in ['udp', 'tcp', 'icmp']:
        print('Введен неверный протокол. Требуется udp или tcp или icmp')
        exit(1)
    if args.protocol in ['udp', 'tcp'] and args.port is None:
        print('tcp/udp требуют наличие порта. Введите порт')
        exit(2)

    find_route(args.ip_address, args.protocol, port=args.port,
               timeout=args.timeout, max_req=args.max_req, verbose=args.v,
               v6=args.ipv6, maxttl=args.max_ttl)


if __name__ == '__main__':
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    main()
