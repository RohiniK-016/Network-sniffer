# Network-sniffer
import socket
import struct
import binascii

def create_socket():
    # Create a raw socket
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    return raw_socket

def parse_ethernet_header(packet):
    ethernet_header = packet[0:14]
    eth_header = struct.unpack("!6s6s2s", ethernet_header)
    dest_mac = binascii.hexlify(eth_header[0]).decode()
    src_mac = binascii.hexlify(eth_header[1]).decode()
    eth_protocol = binascii.hexlify(eth_header[2]).decode()
    return dest_mac, src_mac, eth_protocol

def parse_ip_header(packet):
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])
    return version, ihl, ttl, protocol, src_ip, dest_ip

def main():
    raw_socket = create_socket()

    while True:
        packet, addr = raw_socket.recvfrom(65535)
        dest_mac, src_mac, eth_protocol = parse_ethernet_header(packet)
       
        print(f"Destination MAC: {dest_mac}")
        print(f"Source MAC: {src_mac}")
        print(f"Ethernet Protocol: {eth_protocol}")

        if eth_protocol == '0800':  
        # If IP protocol
            version, ihl, ttl, protocol, src_ip, dest_ip = parse_ip_header(packet)
           
            print(f"IP Version: {version}")
            print(f"IHL: {ihl}")
            print(f"TTL: {ttl}")
            print(f"Protocol: {protocol}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dest_ip}")

if __name__ == "__main__":
    main()
