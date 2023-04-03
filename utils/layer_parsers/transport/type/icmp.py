from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.transport.transport import TransportLayer
import struct
from enum import Enum


class ICMPType(Enum):
    ECHO_REPLY = 0
    UNASSIGNED_1 = 1
    UNASSIGNED_2 = 2
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH_DEPRECATED = 4
    REDIRECT = 5
    ALTERNATE_HOST_ADDRESS_DEPRECATED = 6
    UNASSIGNED_3 = 7
    ECHO = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST_DEPRECATED = 15
    INFORMATION_REPLY_DEPRECATED = 16
    ADDRESS_MASK_REQUEST_DEPRECATED = 17
    ADDRESS_MASK_REPLY_DEPRECATED = 18
    RESERVED_SECURITY = 19
    RESERVED_ROBUSTNESS_EXPERIMENT_1 = 20
    RESERVED_ROBUSTNESS_EXPERIMENT_2 = 21
    RESERVED_ROBUSTNESS_EXPERIMENT_3 = 22
    RESERVED_ROBUSTNESS_EXPERIMENT_4 = 23
    RESERVED_ROBUSTNESS_EXPERIMENT_5 = 24
    RESERVED_ROBUSTNESS_EXPERIMENT_6 = 25
    RESERVED_ROBUSTNESS_EXPERIMENT_7 = 26
    RESERVED_ROBUSTNESS_EXPERIMENT_8 = 27
    RESERVED_ROBUSTNESS_EXPERIMENT_9 = 28
    RESERVED_ROBUSTNESS_EXPERIMENT_10 = 29
    TRACEROUTE_DEPRECATED = 30
    DATAGRAM_CONVERSION_ERROR_DEPRECATED = 31
    MOBILE_HOST_REDIRECT_DEPRECATED = 32
    IPV6_WHERE_ARE_YOU_DEPRECATED = 33
    IPV6_I_AM_HERE_DEPRECATED = 34
    MOBILE_REGISTRATION_REQUEST_DEPRECATED = 35
    MOBILE_REGISTRATION_REPLY_DEPRECATED = 36
    DOMAIN_NAME_REQUEST_DEPRECATED = 37
    DOMAIN_NAME_REPLY_DEPRECATED = 38
    SKIP_DEPRECATED = 39
    PHOTURIS = 40
    SEAMOBY_EXPERIMENTAL = 41
    EXTENDED_ECHO_REQUEST = 42
    EXTENDED_ECHO_REPLY = 43
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class ICMP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._type = None
        self._code = None
        self._checksum = None
        self._parse_data()

    def _parse_data(self):
        type_int, self._code, self._checksum = struct.unpack('! B B H', self._transport_data[:4])
        self._type = ICMPType(type_int)
        self._application_type = ApplicationType.UNKNOWN
        self._application_data = self._transport_data[4:]
        return

    def print_data(self):
        print("ICMP Data:")
        print("\t+Type: {}\n"
              "\t+Code: {}\n"
              "\t+Checksum: {}\n"
              "\t+Application Type: {}".format(self._type.name,
                                               self._code,
                                               self._checksum,
                                               self._application_type.name))
        return

    @property
    def type(self) -> ICMPType:
        return self._type

    @property
    def code(self) -> int:
        return self._code

    @property
    def checksum(self) -> int:
        return self._checksum

