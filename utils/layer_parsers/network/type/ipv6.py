from utils.layer_parsers.transport.transport import TransportType
from ipaddress import IPv6Address
import struct
from utils.layer_parsers.network.network import NetworkLayer


class IPv6(NetworkLayer):

    def __init__(self, network_type, network_data):
        NetworkLayer.__init__(self, network_type, network_data)
        self._traffic_class = None
        self._flow_label = None
        self._payload_length = None
        self._hop_limit = None
        self._parse_data()

    def _parse_data(self):
        version_header_length = self._network_data[0]
        self._version = version_header_length >> 4
        self._traffic_class = (version_header_length & 15) * 4
        self._flow_label, self._payload_length, transport_type_no, \
            self._hop_limit, bytes_src_ip, bytes_dest_ip \
            = struct.unpack('! x 3s h B B 16s 16s', self._network_data[:40])

        self._flow_label = int.from_bytes(self._flow_label, 'big')
        self._transport_type = TransportType(transport_type_no)
        self._src_ip = format(IPv6Address(bytes_src_ip))
        self._dest_ip = format(IPv6Address(bytes_dest_ip))
        self._transport_data = self._network_data[40:]
        return

    def print_data(self):
        print("IPV6 Packet:")
        print("\t+Version: {}\n"
              "\t+Traffic Class: {}\n"
              "\t+Flow Label: {}\n"
              "\t+Payload Length: {}\n"
              "\t+Hop Limit: {}\n"
              "\t+Source IP: {}\n"
              "\t+Destination IP: {}\n"
              "\t+Transport Type: {}".format(self._version,
                                             self._traffic_class,
                                             self._flow_label,
                                             self._payload_length,
                                             self._hop_limit,
                                             self._src_ip,
                                             self._dest_ip,
                                             self._transport_type.name))
        return

    @property
    def traffic_class(self):
        return self._traffic_class

    @property
    def flow_label(self):
        return self._flow_label

    @property
    def payload_length(self):
        return self._payload_length

    @property
    def hop_limit(self):
        return self._hop_limit


