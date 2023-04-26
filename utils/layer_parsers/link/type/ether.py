from utils.layer_parsers.network.network import NetworkType
from utils.layer_parsers.link.link import *
import struct


class Ether(LinkLayer):

    def __init__(self, link_type, link_data):
        LinkLayer.__init__(self, link_type,  link_data)
        self._parse_data()

    def _parse_data(self):
        raw_dest_mac, raw_src_mac, network_type_no = struct.unpack('! 6s 6s H', self._link_data[:14])
        self._dest_mac = self._get_mac_addr(raw_mac=raw_dest_mac)
        self._src_mac = self._get_mac_addr(raw_mac=raw_src_mac)
        if network_type_no != 0x8100:
            self._network_type = NetworkType(network_type_no)
            self._network_data = self._link_data[14:]

        # If the machine has VLAN tagging, handle the DOT1Q layer first before passing the rest
        # of the data as network data.
        else:
            self._vlan_type = VLANType.DOT1Q
            vlan_flags, network_type_no = struct.unpack('! H H', self._link_data[14:18])
            self._vlan_priority = (vlan_flags >> 13) & 0xf
            self._vlan_dei = (vlan_flags >> 12) & 0x1
            self._vlan_id = vlan_flags & 0x0fff
            self._network_type = NetworkType(network_type_no)
            self._network_data = self._link_data[18:]
        return

    def print_data(self):
        if self._vlan_type is None:
            print("Ethernet Data:")
            print("\t+Destination MAC: {}\n"
                  "\t+Source MAC: {}\n"
                  "\t+Network Type: {}".format(self._dest_mac,
                                               self._src_mac,
                                               self._network_type.name))
        else:
            print("Ethernet Data:")
            print("\t+Destination MAC: {}\n"
                  "\t+Source MAC: {}\n"
                  "\t+VLAN Type: {}".format(self._dest_mac,
                                            self._src_mac,
                                            self._vlan_type.name))
            print("{} Data:".format(self._vlan_type.name))
            print("\t+Priority: {}\n"
                  "\t+DEI: {}\n"
                  "\t+ID: {}".format(self._vlan_priority,
                                     self._vlan_dei,
                                     self._vlan_id))
        return
