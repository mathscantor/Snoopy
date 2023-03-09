import struct
from utils.layer_parsers.link.mappings import NetworkType


class LinkLayer:

    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.__dest_mac = None
        self.__src_mac = None
        self.__network_type = None
        self.__network_data = None
        self.__parse_link_data()
        return

    def __parse_link_data(self):
        raw_dest_mac, raw_src_mac, network_type_no = struct.unpack('! 6s 6s H', self.raw_data[:14])
        self.__network_type = NetworkType(network_type_no)
        self.__dest_mac = self.__get_mac_addr(raw_mac=raw_dest_mac)
        self.__src_mac = self.__get_mac_addr(raw_mac=raw_src_mac)
        self.__network_data = self.raw_data[14:]
        return

    def __get_mac_addr(self, raw_mac):
        byte_str = map('{:02x}'.format, raw_mac)
        mac_addr = ':'.join(byte_str).upper()
        return mac_addr

    def get_src_mac(self) -> str:
        return self.__src_mac

    def get_dest_mac(self) -> str:
        return self.__dest_mac

    def get_network_type(self) -> NetworkType:
        return self.__network_type

    def get_network_data(self) -> bytes:
        return self.__network_data

    def print_link_data(self):
        print("Ethernet Data:")
        print("\t+Destination MAC: {}\n"
              "\t+Source MAC: {}\n"
              "\t+Network Type: {}".format(self.__dest_mac,
                                           self.__src_mac,
                                           self.__network_type.name))
        return

    def print_raw_network_data(self):
        if self.__network_data is not None and len(self.__network_data) > 0:
            print("raw network data:")
            print(self.__network_data)
        return
