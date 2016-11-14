'''
Author             => Mher Margaryan
Date               => 2016 November
Python Version     => 3.5
OS                 => Linux, Ubuntu 16.04
'''
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ethernet protocol')
        print('Destination: {}, Source: {}, Protocol: {} ' . format(dest_mac, src_mac, eth_proto))

        # Check if using regular ethernet protocol 8
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}' . format(version, header_length, ttl))
            print(TAB_3 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            if proto == 1:
                (icmp_type, code, checksum, data) = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}' . format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 6:
                (src_port, dest_port, sequence, acknoledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknoledgement: {}'.format(sequence, acknoledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FYN: {}' . format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))

            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data: ')
            print(format_multi_line(DATA_TAB_1, data))

# Unpack ethernet frame
# If you don't understand what's going on, please refer to https://en.wikipedia.org/wiki/Endianness
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[:14]

# Human readable mac address
def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_addr).upper()

# Unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return  version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknoledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fyn = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknoledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fyn, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format multi-line data
def format_multi_line(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return  '\n' . join([prefix + line for line in textwrap.wrap(string, size)])

main()