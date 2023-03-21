#!/usr/bin/python
import socket
import struct

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

# Function to unpack and return ethernet header values
def get_ethernet_header(frm: bytes):
    unpacked_frm = struct.unpack('!6s6sH', frm)

    _src_MAC = unpacked_frm[0].hex(':')
    _dst_MAC = unpacked_frm[1].hex(':')
    _protocol = socket.htons(unpacked_frm[2])

    data = {'Source MAC':_src_MAC,
    'Destination MAC':_dst_MAC,
    'Protocal':_protocol,}
    
    return data


# Function to unpack the packet and return ip header data
def get_ip_header(pkt: bytes):

    unpacked_pkt=struct.unpack("!BBHHHBBH4s4s", pkt)

    _version_headerlenghth =unpacked_pkt[0] # Bytes containing version and hlen
    _tos =unpacked_pkt[1]
    _total_length =unpacked_pkt[2]
    _identification =unpacked_pkt[3]
    _flag_Offset =unpacked_pkt[4] # Bytes containing flag values and fragment offset
    _ttl =unpacked_pkt[5]
    _protocol =unpacked_pkt[6]
    _header_checksum =unpacked_pkt[7]
    _source_address =socket.inet_ntoa(unpacked_pkt[8])
    _destination_address =socket.inet_ntoa(unpacked_pkt[9])

    # Extracting version and hlen from first byte
    _version = _version_headerlenghth >> 4
    _header_length= _version_headerlenghth & 15

    # Extracting flags from _fragment_Offset, currently not returned by this function
    _x_bit = (_flag_Offset >> 15) & 1
    DFF = (_flag_Offset >> 14) & 1
    MFF = (_flag_Offset >> 13) & 1

    _fragment_Offset = _flag_Offset & 8191
    
    data={"Version": _version,
    "Header Lenght": _header_length,
    "Tos": _tos,
    "Total Length": _total_length,
    "Identification": _identification,
    "Fragment Offset": _fragment_Offset,
    "TTL": _ttl,
    "Protocol": _protocol,
    "Header CheckSum": _header_checksum,
    "Source Address": _source_address,
    "Destination Address": _destination_address}

    return data

# Function to unpack and return tcp header values
def get_tcp_header(sgmt: bytes):

    unpacked_sgmt =struct.unpack('!HHLLBBHHH',sgmt[0:20]) # TCP header is 20bytes

    _source_port =unpacked_sgmt[0]
    _destination_port =unpacked_sgmt[1]
    _sequence_number =unpacked_sgmt[2]
    _acknowledge_number =unpacked_sgmt[3]
    _offset_reserved =unpacked_sgmt[4]
    _tcp_flag =unpacked_sgmt[5]
    _window =unpacked_sgmt[6]
    _checksum =unpacked_sgmt[7]
    _urgent_pointer =unpacked_sgmt[8]
    _tcp_data = sgmt[20:]

    # Separating offset and reserved
    _offset = _offset_reserved >> 4
    _reserved = _offset_reserved & 15

    # Extracting TCP flags, not returned by the function
    cwr = (_tcp_flag >> 7) & 1
    ece = (_tcp_flag >> 6) & 1
    urg = (_tcp_flag >> 5) & 1
    ack = (_tcp_flag >> 4) & 1
    psh = (_tcp_flag >> 3) & 1
    rst = (_tcp_flag >> 2) & 1
    syn = (_tcp_flag >> 1) & 1
    fin = _tcp_flag & 1

    data={"Source Port":_source_port,
    "Destination Port":_destination_port,
    "Sequence Number":_sequence_number,
    "Acknowledge Number":_acknowledge_number,
    "Offset": _offset,
    "Reserved": _reserved,
    "Window":_window,
    "CheckSum":_checksum,
    "Urgent Pointer":_urgent_pointer,
    "Data":_tcp_data}

    return data 


def main():
    # Initialize socket
    s = init_socket()

    # Capture traffic until keyboard interrupt
    while True:
        try:
            raw_data, addr = s.recvfrom(65565) #Get data from socket. Firewall may need to be turned off to receive packets

            eth_header = get_ethernet_header(raw_data[0:14]) # Get Ethernet header values 14bytes
            print('\n\n[+] Ethernet Header')
            for key, value in eth_header.items(): # Print ethernet header 14bytes
                print('\t{0} : {1}'.format(key, value))


            ip_header = get_ip_header(raw_data[14:34]) # Get IP header values 20bytes
            print('[+] IP Header')
            for key, value in ip_header.items(): # Print ip header
                print('\t{0} : {1}'.format(key, value))

            if(ip_header["Protocol"]==6): #TCP data
                tcp_header = get_tcp_header(raw_data[34:]) # Get TCP header values 20bytes

                print("[+] TCP Header") # Print TCP header
                for key, value in tcp_header.items():
                    print("\t{0} : {1}".format(key, value))
        
        except KeyboardInterrupt:
            print('Keyboard interrupt received. Quitting')
            break

    s.close() # Close the socket at the end

if (__name__=='__main__'):
    main()
