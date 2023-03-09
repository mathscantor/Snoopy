import struct
from utils.layer_parsers.link.mappings import NetworkType
from utils.layer_parsers.network.mappings import TransportType
from ipaddress import IPv6Address
from ipaddress import IPv4Address


class NetworkLayer:

    def __init__(self, network_type, network_data):

        self.__network_type = network_type
        if self.__network_type == NetworkType.UNKNOWN:
            print("Error in network type! Unable to do parsing in utils/layer_parsers/network.py!")
            print("Exiting...")
            exit(1)

        self.__network_data = network_data
        self.__version = None
        self.__transport_type = None
        self.__transport_data = None
        ## IPV4
        self.__ipv4_header_length = None
        self.__ipv4_time_to_live = None
        self.__ipv4_src_ip = None
        self.__ipv4_dest_ip = None

        ## IPV6
        self.__ipv6_traffic_class = None
        self.__ipv6_traffic_class = None
        self.__ipv6_flow_label = None
        self.__ipv6_payload_length = None
        self.__ipv6_hop_limit = None
        self.__ipv6_src_ip = None
        self.__ipv6_dest_ip = None
        self.parse_network_data()


    def parse_network_data(self):
        if self.__network_type == NetworkType.IPV4:
            self.__parse_ipv4_data()
        elif self.__network_type == NetworkType.IPV6:
            self.__parse_ipv6_data()
        return

    def __parse_ipv4_data(self):
        version_header_length = self.__network_data[0]
        self.__version = version_header_length >> 4
        self.__ipv4_header_length = (version_header_length & 15) * 4
        self.__ipv4_time_to_live, transport_type_no, \
            bytes_src_ip, bytes_dest_ip = struct.unpack('! 8x B B 2x 4s 4s',
                                                        self.__network_data[:20])
        self.__transport_type = TransportType(transport_type_no)
        self.__ipv4_src_ip = format(IPv4Address(bytes_src_ip))
        self.__ipv4_dest_ip = format(self.form_proper_ipv4(bytes_dest_ip))
        self.__transport_data = self.__network_data[self.__ipv4_header_length:]
        return

    def __parse_ipv6_data(self):
        version_header_length = self.__network_data[0]
        self.__version = version_header_length >> 4
        self.__ipv6_traffic_class = (version_header_length & 15) * 4
        self.__ipv6_flow_label, self.__ipv6_payload_length, transport_type_no, \
            self.__ipv6_hop_limit, bytes_src_ip, bytes_dest_ip \
            = struct.unpack('! x 3s h B B 16s 16s', self.__network_data[:40])

        self.__ipv6_flow_label = int.from_bytes(self.__ipv6_flow_label, 'big')
        self.__transport_type = TransportType(transport_type_no)
        self.__ipv6_src_ip = format(IPv6Address(bytes_src_ip))
        self.__ipv6_dest_ip = format(IPv6Address(bytes_dest_ip))
        self.__transport_data = self.__network_data[40:]
        return

    def form_proper_ipv4(self, addr):
        return '.'.join(map(str, addr))

    def get_version(self):
        return self.__version

    def get_transport_type(self):
        return self.__transport_type

    def get_transport_data(self):
        return self.__transport_data

    def get_ip_header_length(self):
        return self.__ipv4_header_length

    def get_src_ip(self):
        return self.ipv4_src_ip

    def get_dest_ip(self):
        return self.ipv4_dest_ip


    def get_time_to_live(self):
        return self.ipv4_time_to_live

    def print_raw_transport_data(self):
        if self.__transport_data is not None and len(self.__transport_data) > 0:
            print("raw transport data:")
            print(self.__transport_data)
        return

    def print_network_data(self):
        if self.__network_type == NetworkType.IPV4:
            self.__print_ipv4_data()
        elif self.__network_type == NetworkType.IPV6:
            self.__print_ipv6_data()
        return

    def __print_ipv4_data(self):
        print("IPV4 Packet:")
        print("\t+Version: {}\n"
              "\t+Header Length: {}\n"
              "\t+Time To Live: {}\n"
              "\t-Source IP: {}\n"
              "\t+Destination IP: {}\n"
              "\t+Transport Type: {}".format(self.__version,
                                             self.__ipv4_header_length,
                                             self.__ipv4_time_to_live,
                                             self.__ipv4_src_ip,
                                             self.__ipv4_dest_ip,
                                             self.__transport_type.name))

    def __print_ipv6_data(self):
        #self.__ipv6_flow_label, self.__ipv6_payload, self.__transport_type, \
            #self.__ipv6_hop_limit, self.__ipv6_src_ip, self.__ipv6_dest_ip \
        print("IPV6 Packet:")
        print("\t+Version: {}\n"
              "\t+Traffic Class: {}\n"
              "\t+Flow Label: {}\n"
              "\t+Payload Length: {}\n"
              "\t+Hop Limit: {}\n"
              "\t+Source IP: {}\n"
              "\t+Destination IP: {}\n"
              "\t+Transport Type: {}".format(self.__version,
                                             self.__ipv6_traffic_class,
                                             self.__ipv6_flow_label,
                                             self.__ipv6_payload_length,
                                             self.__ipv6_hop_limit,
                                             self.__ipv6_src_ip,
                                             self.__ipv6_dest_ip,
                                             self.__transport_type.name))
        return