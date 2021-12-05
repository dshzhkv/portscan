import argparse
import socket
import struct
import time
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr, sr1
from scapy.supersocket import L3RawSocket
from scapy.volatile import RandShort
from multiprocessing.dummy import Pool
import random

PORT = random.randint(1, 65535)
PACKAGES = {
    'HTTP': b'GET / HTTP/1.1',
    "DNS": struct.pack("!HHHHHH", PORT, 256, 1, 0, 0, 0) +
            b"\x06github\x03com\x00\x00\x01\x00\x01",
    "ECHO": b"ping"
}


def get_ports_info(args):
    result = {'tcp': set(), 'udp': set()}

    for record in args.ports:
        if '/' in record:
            connection_type, ports = record.split('/')
            for port in ports.split(','):
                if '-' in port:
                    range_start = int(port.split('-')[0])
                    range_end = int(port.split('-')[1])
                    for p in range(range_start, range_end + 1):
                        result[connection_type].add(p)
                else:
                    result[connection_type].add(int(port))
        else:
            connection_type = record
            for port in range(1, 65536):
                result[connection_type].add(port)

    tcp_ports = [(args.IP_ADDRESS, port, args.verbose, args.guess,
                  args.timeout) for port in result['tcp']]
    udp_ports = [(args.IP_ADDRESS, port, args.guess, args.timeout) for port
                 in result['udp']]

    return tcp_ports, udp_ports


def scan(args):
    tcp_ports, udp_ports = get_ports_info(args)

    scan_connection('tcp', tcp_ports)
    scan_connection('udp', udp_ports)


def scan_connection(connection_type, ports):
    pool = Pool(100)

    if connection_type == 'tcp':
        result = pool.imap(scan_tcp, ports)
    else:
        result = pool.imap(scan_udp, ports)

    while True:
        try:
            result.next()
        except (ConnectionResetError, StopIteration):
            break

    pool.close()
    pool.terminate()


def scan_udp(args):
    protocol = '-'
    ip, port, guess, timeout = args
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    for package in PACKAGES.keys():
        try:
            address = (ip, port)
            message = PACKAGES[package]
            sock.sendto(message, address)
            data, _ = sock.recvfrom(1024)
            if guess:
                protocol = get_udp_protocol(data, PORT, message)
            if data:
                print("UDP", port, protocol)
                break
        except socket.timeout:
            pass
    sock.close()


def get_udp_protocol(data, port, message):
    if data.startswith(b"HTTP"):
        return "HTTP"
    elif struct.pack("!H", port) in data:
        return "DNS"
    elif message == data:
        return "ECHO"
    return '-'


def scan_tcp(args):
    ip, port, verbose, guess, timeout = args
    start_time = time.perf_counter()
    conf.L3socket = L3RawSocket

    src_port = RandShort()
    package = IP(dst=ip) / TCP(sport=src_port, dport=port, flags='S')

    response = sr1(package, timeout=timeout, verbose=0)
    elapsed = 0
    protocol = ''
    sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags='AR'), timeout=1,
       verbose=0)
    if verbose:
        elapsed = time.perf_counter() - start_time
    if response is None:
        pass
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        if guess:
            protocol = get_tcp_protocol(response)
        if verbose:
            elapsed = str(round(elapsed * 1000, 3))
        else:
            elapsed = ''
        print("TCP", port, elapsed, protocol)


def get_tcp_protocol(response):
    protocol = response.sprintf("%TCP.sport%")
    if protocol == "domain":
        return "DNS"
    return protocol.upper()


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--timeout", type=int, default=2,
                        help='таймаут ожидания ответа (по умолчанию 2с)')
    parser.add_argument('-v', '--verbose', action="store_true",
                        help='подробный режим')
    parser.add_argument('-g', '--guess', action="store_true",
                        help='определение протокола прикладного уровня')

    parser.add_argument("IP_ADDRESS", type=str, help='ip адрес')

    parser.add_argument('ports', type=str, nargs='+',
                        help='{tcp|udp}[/[PORT|PORT-PORT],...]')

    args = parser.parse_args()

    return args


def main():
    args = get_args()
    scan(args)


if __name__ == '__main__':
    main()
