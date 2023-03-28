from utils.layer_parsers.transport.transport import TransportType
from ipaddress import IPv4Address
import struct
from utils.layer_parsers.network.network import NetworkLayer


class IPv4(NetworkLayer):

    def __init__(self, network_type, network_data):
        NetworkLayer.__init__(self, network_type, network_data)
        self._ip_header_length = None
        self._time_to_live = None
        self._parse_data()

    def __form_proper_ipv4(self, addr):
        return '.'.join(map(str, addr))

    def _parse_data(self):
        version_header_length = self._network_data[0]
        self._version = version_header_length >> 4
        self._ip_header_length = (version_header_length & 15) * 4
        self._time_to_live, transport_type_no, \
            bytes_src_ip, bytes_dest_ip = struct.unpack('! 8x B B 2x 4s 4s',
                                                        self._network_data[:20])
        self._transport_type = TransportType(transport_type_no)
        self._src_ip = format(IPv4Address(bytes_src_ip))
        self._dest_ip = format(self.__form_proper_ipv4(bytes_dest_ip))
        self._transport_data = self._network_data[self._ip_header_length:]
        return

    def print_data(self):
        print("IPV4 Packet:")
        print("\t+Version: {}\n"
              "\t+Header Length: {}\n"
              "\t+Time To Live: {}\n"
              "\t-Source IP: {}\n"
              "\t+Destination IP: {}\n"
              "\t+Transport Type: {}".format(self._version,
                                             self._ip_header_length,
                                             self._time_to_live,
                                             self._src_ip,
                                             self._dest_ip,
                                             self._transport_type.name))

    @property
    def ip_header_length(self) -> int:
        return self._ip_header_length

    @property
    def time_to_live(self) -> int:
        return self._time_to_live

