'''Following tutorial https://www.bitforestinfo.com/blog/02/15/how-to-write-simple-packet-sniffer.html'''

#!/usr/bin/python
import socket
import struct
import binascii

# Creating a socket
def get_socket():
    '''
    AF_INET specifies IPv4 address family
    RAW socket to capture IP protocal traffic
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) # Requires admin privileges for RAW sockets

    # Windows specific options for the socket
    s.bind(("192.168.0.227", 0)) # Interface IP
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) # Set promiscuous mode

    return s


# Function to unpack the packet and get ethernet header data
def get_ethernet_header(pkt):

    unpacked_pkt = struct.unpack('!6s6sH', pkt) # Unpack

    dest_MAC = binascii.hexlify(unpacked_pkt[0])
    src_MAC = binascii.hexlify(unpacked_pkt[1])
    proto_type = unpacked_pkt[2]

    data = {'Destination MAC': dest_MAC,\
            'Source MAC': src_MAC,\
            'Protocal': proto_type}
    
    return data

s = get_socket()
while True:
    packet = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets

    eth_header = get_ethernet_header(packet[0][0:14]) # Get ethernet header values

    print('\n')
    for key, value in eth_header.items(): # Print header
        print('{0} : {1}'.format(key, value))
