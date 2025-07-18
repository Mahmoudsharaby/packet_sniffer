from socket import *
import sys
import struct
import textwrap

tab_1='\t - '
tab_2='\t\t - '
tab_3='\t\t\t - '
tab_4='\t\t\t\t -  '

data_tab_1='\t '
data_tab_2='\t\t '
data_tab_3='\t\t\t '
data_tab_4='\t\t\t\t'

def main():
    conn=socket(AF_PACKET,SOCK_RAW,ntohs(3))
    while True:
        raw_data,addr=conn.recvfrom(65565)
        dest_mac,src_mac,proto,data= ethernet_frame(raw_data)
        print("Ethernet frame received:\n")
        print("Destination MAC:{}, Source mac:{}, Protocol:{}".format(dest_mac,src_mac,proto))
        print('\n')

        if proto==8:
            (version,header_length,ttl,proto,src,dest,data)=IP_datagram(data)
            print(tab_1+"IP datagram of IPv4 received:\n")
            print(tab_2+"version:{}, Header length:{}, TTL:{}, Protocol:{}\n".format(version,header_length,ttl,proto))
            print(tab_3+"Source IP:{}, Destination IP:{} \n".format(src,dest))

            if proto == 1:
                (icmp_type,code,checksum,data)=icmp_packet(data)
                print(tab_1+"ICMP packet of IPv4 received:\n")
                print(tab_2+"code:{}, checksum:{}, ICMP_type:{}\n".format(code,checksum,icmp_type))
                print(tab_2+"data:\n")
                print(format_multi_line_data(data_tab_3,data))

            elif proto == 6:
                (src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data)=tcp_segment(data)
                print(tab_1+"TCP segment of IPv4 received:\n")
                print(tab_2+'Source Port:{},Destination Port:{}\n'.format(src_port,dest_port))
                print(tab_2+'Sequence:{},ACKnowledgment:{}\n'.format(sequence,acknowledgement))
                print(tab_2+'Flags:\n')
                print(tab_3+'URG:{}, ACK:{}, PSH:{}, RST:{},SYN:{},FIN:{}\n'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_fin,data))
                print(format_multi_line_data(data_tab_3,data))
            elif proto == 17:
                (src_port, dest_port, size, data)=udp_segment(data)
                print(tab_1+"UDP segment of IPv4 received:\n")
                print(tab_2+'Source Port:{},Destination Port:{}, Size:{}\n'.format(src_port,dest_port,size))
                print(format_multi_line_data(data_tab_3, data))
            else:
                print(tab_1+'Data:')
                print(format_multi_line_data(data_tab_3, data))


def ethernet_frame(data):
    dest_mac,src_mac,proto=struct.unpack("! 6s 6s H",data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),htons(proto),data[14:]

def get_mac_addr(addr):
    bytes=map('{:02x}'.format,addr)
    return ':'.join(bytes).upper()

def IP_datagram(data):
    version_header_length=data[0]
    version=version_header_length>>4
    header_length=(version_header_length&15)*4 # to get the index of the data(payload)
    TTL,proto,src_IP,dest_IP=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_length,TTL,proto,ipv4(src_IP),ipv4(dest_IP),data[header_length:]

# return a properly formatted IPV4 address
def ipv4(IP):
    return '.'.join(map(str,IP))
# unpacks ICmp packet
def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('! B B H',data[:4])
    return icmp_type,code,ckecksum, data[4:]
# unpack TCP segment
def tcp_segment(data):
    (src_port,dest_port,sequence,acknowledgement, offset_reservedflag)=struct.unpack('! H H L L H',data[:14])
    offset=(offset_reservedflag>>12)*4
    flag_urg=(offset_reservedflag&32)>>5
    flag_ack = (offset_reservedflag &16) >> 4
    flag_psh= (offset_reservedflag & 8) >> 3
    flag_rst = (offset_reservedflag & 4) >> 2
    flag_syn = (offset_reservedflag & 2) >> 1
    flag_fin= (offset_reservedflag & 1)
    return  src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]
def udp_segment(data):
    src_port,dest_port,size=struct.unpack('! H H 2x H',data[:8])
    return src_port,dest_port, size, data[8:]

def format_multi_line_data(prefix,string,size=80):
    size=size-len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size-=1
    return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])
main()