#!/usr/bin/python3
import socket
from core import *

# Initialyzing socket
def init_socket():

    HOST = (socket.gethostbyname(socket.getfqdn())) # Get local ip

    '''
    AF_INET - specifies IPv4 address family
    PF_PACKET - allows device level network interace (Linux only)
    RAW socket to capture IP traffic
    '''
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # Requires admin privileges for RAW sockets

    # Windows platform specific options for the socket
    #s.bind((HOST, 0)) # Interface IP
    #s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    #s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) # Set promiscuous mode

    return s


def main():
    # Initialize socket
    s = init_socket()

    # Capture traffic until keyboard interrupt
    while True:
        try:
            raw_data, addr = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets

            eth_header, eth_data = get_ethernet_header(raw_data) # Get Ethernet header values 14bytes
            print('\n\n[+] Ethernet Header')
            for key, value in eth_header.items():
                print('\t{0} : {1}'.format(key, value))


            ip_header, ip_data = get_ip_header(eth_data) # Get IP header
            print('[+] IP Header')
            for key, value in ip_header.items():
                print('\t{0} : {1}'.format(key, value))

            if(ip_header["Protocol"]==6): #TCP data
                tcp_header, tcp_data = get_tcp_header(ip_data) # Get TCP header

                print("[+] TCP Header")
                for key, value in tcp_header.items():
                    print("\t{0} : {1}".format(key, value))

                print('[-] TCP Data\n {}'.format(tcp_data))

            elif (ip_header["Protocol"]==17): # UDP datagram
                udp_header, udp_data = get_udp_header(ip_data)

                print("[+] UDP Header")
                for key, value in udp_header:
                    print("{0}: {1}".format(key, value))

                print("[-] UDPData\n{}".format(udp_data))
        
        except KeyboardInterrupt:
            print('\nKeyboard interrupt received. Quitting')
            break

    s.close() # Close the socket at the end

if (__name__=='__main__'):
    main()
