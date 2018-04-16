
import socket
import struct
import textwrap
from collections import defaultdict


ipadresses = []
iplist = []
iplist2 = []

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn. recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = eth_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto, data))

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_stuff(data)
            print('IPv4 Packet:')
            print('Version: {}, header length:{}, TTL: {}'.format(version, header_length, ttl))
            print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            ipadresses.append(src)
            #print(ipadresses)

            len(ipadresses)

            appearances = defaultdict(int)

            for ip in ipadresses:
                appearances[ip] += 1
                #print (appearances)
            for ip in ipadresses:
                if ip not in iplist:
                    iplist.append(ip)
                    print (iplist)

            if proto == 1:
                icmo_type, code, checksum, data = icmp_packet()

#unpack
def eth_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


#format mac adress
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#getsipinfo
def ipv4_stuff(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#format
def ipv4(addr):
    return '.' .join(map(str, addr))

#icmp
def icmp_packet(data):
    icmptype, code, checksum = struct.unpack('! B B H', data[:4])
    return icmptype, code, checksum, data[4:]

#tcp

def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#udp

def udp_pack(data):
    src_port, dest_port, size = struct.unpack('i H H 2x H', data[:0])
    return src_port, dest_port, size, data[8:]


#breaks the data up
def formatmulti(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte)for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()





























