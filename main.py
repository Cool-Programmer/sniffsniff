'''
Author             => Mher Margaryan
Date               => 2016 November
Python Version     => 3.5
OS                 => Linux, Ubuntu 16.04
'''
import socket
import struct
import textwrap


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ethernet protocol')
        print('Destination: {}, Source: {}, Protocol: {} ' . format(dest_mac, src_mac, eth_proto))



# Unpack ethernet frame
# If you don't understand what's going on, please refer to https://en.wikipedia.org/wiki/Endianness
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[:14]

# Human readable mac address
def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_addr).upper()

main()