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

# Function to unpack the packet and get ip header data
def get_ip_header(pkt):

    unpacked_pkt=struct.unpack("!BBHHHBBH4s4s", pkt)

    _version =unpacked_pkt[0] 
    _tos=unpacked_pkt[1]
    _total_length =unpacked_pkt[2]
    _identification =unpacked_pkt[3]
    _fragment_Offset =unpacked_pkt[4]
    _ttl =unpacked_pkt[5]
    _protocol =unpacked_pkt[6]
    _header_checksum =unpacked_pkt[7]
    _source_address =socket.inet_ntoa(unpacked_pkt[8])
    _destination_address =socket.inet_ntoa(unpacked_pkt[9])
    
    data={'Version':_version,
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
    s = get_socket()

    # Sniff traffic until keyboard interrupt
    while True:
        try:
            packet = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets

            eth_header = get_ip_header(packet[0][0:20]) # Get IP header values

            print('\n\n[+] IP Header')
            for key, value in eth_header.items(): # Print header
                print('\t{0} : {1}'.format(key, value))
        
        except KeyboardInterrupt:
            print('Keyboard interrupt received. Quitting')
            break

    s.close() # Close the socket at the end

if (__name__=='__main__'):
    main()
