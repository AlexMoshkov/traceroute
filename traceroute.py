import ipwhois
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


def find_route(address: str, protocol: str, port: int = 53, timeout: float = 2,
               max_req: int = 3, verbose: bool = False, v6: bool = False,
               maxttl: int = 64):
    proto_packet = TCP(sport=10101, dport=port)
    if protocol == 'udp':
        proto_packet = UDP(sport=10101, dport=[port])
    elif protocol == 'icmp':
        if v6:
            proto_packet = ICMPv6EchoRequest()
        else:
            proto_packet = ICMP()

    for i in range(1, maxttl):
        times: list[str] = []
        ip = '*'
        for _ in range(max_req):
            if v6:
                packet = IPv6(dst=address, hlim=i) / proto_packet
            else:
                packet = IP(dst=address, ttl=i) / proto_packet
            answer = sr1(packet, verbose=0, timeout=timeout)
            if answer is not None:
                ip = answer[IP].src
                times.append(str(round((answer.time - packet.sent_time) * 1000,
                                       2)) + ' ms')
            else:
                times.append('*')

        verbose_info = ''
        if ip != '*':
            try:
                verbose_info = "" if not verbose else \
                ipwhois.IPWhois(ip).lookup_whois()['asn']
            except:
                verbose_info = 'NA'
        print(f"{i}. {ip}", ' '.join(times), verbose_info)
        if ip == address:
            break


if __name__ == '__main__':
    find_route('8.8.8.8', 'icmp', verbose=True, timeout=1)
