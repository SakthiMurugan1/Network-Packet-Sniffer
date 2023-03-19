#!/usr/bin/python
import socket
import struct

# Creating a socket
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

# Function to unpack and return ethernet header values
def get_ethernet_header(frm: bytes):
    unpacked_frm = struct.unpack('!6s6sH', frm)

    _src_MAC = unpacked_frm[0].hex(':')
    _dst_MAC = unpacked_frm[1].hex(':')
    _protocol = socket.htons(unpacked_frm[2])

    data = {'Source MAC':_src_MAC,
    'Destination MAC':_dst_MAC,
    'Protocal':_protocol}
    
    return data


# Function to unpack the packet and return ip header data
def get_ip_header(pkt: bytes):

    unpacked_pkt=struct.unpack("!BBHHHBBH4s4s", pkt)

    _version =unpacked_pkt[0] 
    _tos =unpacked_pkt[1]
    _total_length =unpacked_pkt[2]
    _identification =unpacked_pkt[3]
    _fragment_Offset =unpacked_pkt[4]
    _ttl =unpacked_pkt[5]
    _protocol =unpacked_pkt[6]
    _header_checksum =unpacked_pkt[7]
    _source_address =socket.inet_ntoa(unpacked_pkt[8])
    _destination_address =socket.inet_ntoa(unpacked_pkt[9])
    
    data={'Version':_version,\
    "Tos":_tos,
    "Total Length":_total_length,
    "Identification":_identification,
    "Fragment":_fragment_Offset,
    "TTL":_ttl,
    "Protocol":_protocol,
    "Header CheckSum":_header_checksum,
    "Source Address":_source_address,
    "Destination Address":_destination_address}

    return data


def main():
    # Initialize socket
    s = init_socket()

    # Capture traffic until keyboard interrupt
    while True:
        try:
            raw_data = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets

            eth_header = get_ethernet_header(raw_data[0][0:14]) # Get Ethernet header values
            print('\n\n[+] Ethernet Header')
            for key, value in eth_header.items(): # Print ethernet header
                print('\t{0} : {1}'.format(key, value))


            ip_header = get_ip_header(raw_data[0][14:34]) # Get IP header values
            print('\n[+] IP Header')
            for key, value in ip_header.items(): # Print header
                print('\t{0} : {1}'.format(key, value))
        
        except KeyboardInterrupt:
            print('Keyboard interrupt received. Quitting')
            break

    s.close() # Close the socket at the end

if (__name__=='__main__'):
    main()
