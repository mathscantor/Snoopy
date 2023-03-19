from utils.layer_parsers.network.network import NetworkType
from utils.layer_parsers.link.link import LinkLayer
import struct


class Ether(LinkLayer):

    def __init__(self, link_type, link_data):
        LinkLayer.__init__(self, link_type,  link_data)
        self._parse_data()

    def _parse_data(self):
        raw_dest_mac, raw_src_mac, network_type_no = struct.unpack('! 6s 6s H', self._link_data[:14])
        self._network_type = NetworkType(network_type_no)
        self._dest_mac = self._get_mac_addr(raw_mac=raw_dest_mac)
        self._src_mac = self._get_mac_addr(raw_mac=raw_src_mac)
        self._network_data = self._link_data[14:]
        return

    def print_data(self):
        print("Ethernet Data:")
        print("\t+Destination MAC: {}\n"
              "\t+Source MAC: {}\n"
              "\t+Network Type: {}".format(self._dest_mac,
                                           self._src_mac,
                                           self._network_type.name))
        return
