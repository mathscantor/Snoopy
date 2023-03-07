import socket
import struct
import fcntl
from utils.mappings import *

class Packet:

    def __init__(self, raw_data):
        self.description = "Packet class that provides utility for parsing packet headers"
        self.raw_data = raw_data

        # Link Data
        self.dest_mac = None
        self.src_mac = None
        self.ethernet_type = None
        self.network_data = None
        self.parse_link_data()

        # Network Data
        ## IPV4
        self.ipv4_version = None
        self.ipv4_header_length = None
        self.ipv4_time_to_live = None
        self.ipv4_transport_type = None
        self.ipv4_src_ip = None
        self.ipv4_dest_ip = None
        self.ipv4_transport_data = None
        self.parse_network_data()

        # Transport Data
        # ICMP
        self.icmp_type = None
        self.icmp_code = None
        self.icmp_checksum = None

        self.src_port = None
        self.dest_port = None
        # TCP
        self.sequence = None
        self.acknowledgment = None
        self.offset = None
        self.flag_urg = None
        self.flag_ack = None
        self.flag_psh = None
        self.flag_rst = None
        self.flag_syn = None
        self.flag_fin = None
        self.parse_transport_data()

    def parse_link_data(self):
        raw_dest_mac, raw_src_mac, ethernet_type_no = struct.unpack('! 6s 6s H', self.raw_data[:14])
        self.ethernet_type = NetworkType(ethernet_type_no)
        self.dest_mac = self.get_mac_addr(raw_mac=raw_dest_mac)
        self.src_mac = self.get_mac_addr(raw_mac=raw_src_mac)
        self.network_data = self.raw_data[14:]

    def get_mac_addr(self, raw_mac):
        byte_str = map('{:02x}'.format, raw_mac)
        mac_addr = ':'.join(byte_str).upper()
        return mac_addr

    def parse_network_data(self):
        version_header_length = self.network_data[0]
        self.ipv4_version = version_header_length >> 4
        self.ipv4_header_length = (version_header_length & 15) * 4
        self.ipv4_time_to_live, protocol_no, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', self.network_data[:20])
        self.ipv4_transport_type = TransportType(protocol_no)
        self.ipv4_src_ip = self.get_ip(src_ip)
        self.ipv4_dest_ip = self.get_ip(dest_ip)
        self.ipv4_transport_data = self.network_data[self.ipv4_header_length:]
        return

    def get_ip(self, addr):
        return '.'.join(map(str, addr))

    def parse_transport_data(self):
        if self.ipv4_transport_type == TransportType.ICMP:
            self.__parse_icmp_data()
        elif self.ipv4_transport_type == TransportType.TCP:
            self.__parse_tcp_data()
        elif self.ipv4_transport_data == TransportType.UDP:
            self.__parse_udp_data()
        elif self.ipv4_transport_data == TransportType.SCTP:
            self.__parse_sctp_data()
        return

    def __parse_tcp_data(self):
        self.src_port, \
            self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H',
                                                                                                      self.ipv4_transport_data[:14])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        return

    def __parse_icmp_data(self):
        self.icmp_type, self.icmp_code, self.icmp_checksum = struct.unpack('! B B H', self.network_data[:4])
        return

    def __parse_udp_data(self):
        return

    def __parse_sctp_data(self):
        return

    def get_src_mac(self):
        return self.src_mac

    def get_dest_mac(self):
        return self.dest_mac

    def get_ethernet_type(self):
        return self.ethernet_type

    def get_ip_data(self):
        return self.network_data

    def get_ipv4_version(self):
        return self.ipv4_version

    def get_ip_header_length(self):
        return self.ipv4_header_length

    def get_src_ip(self):
        return self.ipv4_src_ip

    def get_dest_ip(self):
        return self.ipv4_dest_ip

    def get_protocol(self):
        return self.ipv4_transport_type

    def get_protocol_data(self):
        return self.ipv4_transport_data

    def get_time_to_live(self):
        return self.ipv4_time_to_live

    def get_icmp_type(self):
        return self.icmp_type

    def get_icmp_code(self):
        return self.icmp_code

    def get_icmp_checksum(self):
        return self.icmp_checksum

    def print_ethernet_data(self):
        print("Ethernet Data:")
        print("\t+Destination MAC: {}\n"
              "\t+Source MAC: {}\n"
              "\t+Ethernet Type: {}".format(self.dest_mac,
                                            self.src_mac,
                                            self.ethernet_type.name))

    def print_ip_data(self):
        if self.ethernet_type == NetworkType.IPV4:
            self.__print_ipv4_data()
        elif self.ethernet_type == NetworkType.IPV6:
            self.__print_ipv6_data()
        return

    def print_protocol_data(self):
        if self.ipv4_transport_type == TransportType.ICMP:
            self.__print_icmp_data()
        elif self.ipv4_transport_type == TransportType.TCP:
            self.__print_tcp_data()
        elif self.ipv4_transport_data == TransportType.UDP:
            self.__print_udp_data()
        elif self.ipv4_transport_data == TransportType.SCTP:
            self.__print_sctp_data()

    def __print_ipv4_data(self):
        print("IPV4 Packet:")
        print("\t+Version: {}\n"
              "\t+Header Length: {}\n"
              "\t+Time To Live: {}\n"
              "\t+Protocol: {}\n"
              "\t-Source IP: {}\n"
              "\t+Destination IP: {}".format(self.ipv4_version,
                                             self.ipv4_header_length,
                                             self.ipv4_time_to_live,
                                             self.ipv4_transport_type.name,
                                             self.ipv4_src_ip,
                                             self.ipv4_dest_ip))

    def __print_ipv6_data(self):
        return

    def __print_tcp_data(self):
        print("TCP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Sequence: {}\n"
              "\t+Acknowledgement: {}\n"
              "\t+Offset: {}\n"
              "\t+FLAGS:\n"
              "\t\t+URG: {}\n"
              "\t\t+ACK: {}\n"
              "\t\t+PSH: {}\n"
              "\t\t+RST: {}\n"
              "\t\t+SYN: {}\n"
              "\t\t+FIN: {}".format(self.src_port,
                                    self.dest_port,
                                    self.sequence,
                                    self.acknowledgment,
                                    self.offset,
                                    self.flag_urg,
                                    self.flag_ack,
                                    self.flag_psh,
                                    self.flag_rst,
                                    self.flag_syn,
                                    self.flag_fin))

    def __print_icmp_data(self):
        print("ICMP Data:")
        print("\t+Type: {}\n"
              "\t+Code: {}\n"
              "\t+Checksum: {}".format(self.icmp_type,
                                       self.icmp_code,
                                       self.icmp_checksum))
        return

