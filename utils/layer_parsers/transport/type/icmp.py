from utils.layer_parsers.transport.mappings import *
from utils.layer_parsers.transport.transport import TransportLayer
import struct


class ICMP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._type = None
        self._code = None
        self._checksum = None
        self._parse_data()

    def _parse_data(self):
        self._type, self._code, self._checksum = struct.unpack('! B B H', self._transport_data[:4])
        self._application_type = ApplicationType.UNKNOWN
        self._application_data = self._transport_data[4:]
        return

    def print_data(self):
        print("ICMP Data:")
        print("\t+Type: {}\n"
              "\t+Code: {}\n"
              "\t+Checksum: {}".format(self.__icmp_type,
                                       self.__icmp_code,
                                       self.__icmp_checksum))
        return

    @property
    def type(self):
        return self._type

    @property
    def code(self):
        return self._code

    @property
    def checksum(self):
        return self._checksum

