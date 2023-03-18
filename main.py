'''Following tutorial https://www.bitforestinfo.com/blog/02/15/how-to-write-simple-packet-sniffer.html'''

#!/usr/bin/python
import socket
import struct
import binascii

# Creating a socket
'''
AF_INET specifies IPv4 address family
RAW socket to capture IP protocal traffic
'''
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) # Requires admin privileges for RAW sockets

# Windows specific options for the socket
s.bind(("192.168.129.157", 0)) # Interface IP
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) # Set promiscuous mode

while True:

    packet = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets


    '''Parse the packet to extract host and dest mac'''
    ethernet_header = packet[0][0:14] # Get Ethernet header
    
    eth_header = struct.unpack("!6s6sH", ethernet_header) # Unpack

    print("Destination MAC: {0} Source MAC: {1} Type: {2}".format\
          (binascii.hexlify(eth_header[0]), binascii.hexlify(eth_header[1]), eth_header[2]))
