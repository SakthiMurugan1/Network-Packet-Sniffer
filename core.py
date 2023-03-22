#!/usr/bin/python3
import struct
import socket

# Function to unpack and return ethernet header values
def get_ethernet_header(frm: bytes):
    unpacked_frm = struct.unpack('!6s6sH', frm[0:14]) # Layer 2 frames headers are 14 bytes

    _src_MAC = unpacked_frm[0].hex(':')
    _dst_MAC = unpacked_frm[1].hex(':')
    _protocol = socket.htons(unpacked_frm[2])

    header = {'Source MAC':_src_MAC,
    'Destination MAC':_dst_MAC,
    'Protocal':_protocol,}
    
    _ethdata = frm[14:]

    return header, _ethdata


# Function to unpack the packet and return ip header data
def get_ip_header(pkt: bytes):

    unpacked_pkt=struct.unpack("!BBHHHBBH4s4s", pkt[0:20]) # IP packet headers are 20 bytes

    _version_headerlenghth =unpacked_pkt[0] # Byte containing version and hlen
    _tos =unpacked_pkt[1]
    _total_length =unpacked_pkt[2]
    _identification =unpacked_pkt[3]
    _flag_Offset =unpacked_pkt[4] # Byte containing flag values and fragment offset
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
    _flags = [_x_bit, DFF, MFF]

    _fragment_Offset = _flag_Offset & 8191
    
    header={"Version": _version,
    "Header Lenght": _header_length,
    "Tos": _tos,
    "Total Length": _total_length,
    "Identification": _identification,
    "Flags": _flags,
    "Fragment Offset": _fragment_Offset,
    "TTL": _ttl,
    "Protocol": _protocol,
    "Header CheckSum": _header_checksum,
    "Source Address": _source_address,
    "Destination Address": _destination_address}

    _ipdata = pkt[20:]

    return header, _ipdata

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
    _flags = [cwr, ece, urg, ack, psh, rst, syn, fin]

    header={"Source Port":_source_port,
    "Destination Port":_destination_port,
    "Sequence Number":_sequence_number,
    "Acknowledge Number":_acknowledge_number,
    "Offset": _offset,
    "Reserved": _reserved,
    "Flags": _flags,
    "Window":_window,
    "CheckSum":_checksum,
    "Urgent Pointer":_urgent_pointer}

    _tcp_data = sgmt[20:]

    return header, _tcp_data

# Function to unpack and return udp headers
def get_udp_header(dgrm: bytes):
    unpacked_dgrm = struct.unpack('!HHHH', dgrm[0:8]) # UDP headers are just 8 bytes

    _source_port = unpacked_dgrm[0]
    _destination_port = unpacked_dgrm[1]
    _total_length = unpacked_dgrm[2]
    _checksum = unpacked_dgrm[3]

    header = {"Source Port": _source_port,
              "Destination Port": _destination_port,
              "Length": _total_length,
              "Checksum": _checksum}
    
    _udp_data = dgrm[8:]

    return header, _udp_data