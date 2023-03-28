from utils.layer_parsers.transport.transport import TransportLayer
from utils.layer_parsers.application.application import ApplicationType
import struct
from enum import Enum


class SCTPType(Enum):
    DATA = 0
    INIT = 1
    INIT_ACK = 2
    SACK = 3
    HEARTBEAT = 4
    HEARTBEAT_ACK = 5
    ABORT = 6
    SHUTDOWN = 7
    SHUTDOWN_ACK = 8
    ERROR = 9
    COOKIE_ECHO = 10
    COOKIE_ACK = 11
    ECNE = 12
    CWR = 13
    SHUTDOWN_COMPLETE = 14
    AUTH = 15
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class SCTP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._verification_tag = None
        self._checksum = None
        self._chunk_type = None
        self._chunk_flags = None
        self._chunk_length = None
        self._parse_data()

    def _parse_data(self):
        self._src_port, self._dest_port, \
            self._verification_tag, self._checksum, \
            self._chunk_type, self._chunk_flags,\
            self._chunk_length = struct.unpack('! H H L L B B H', self._transport_data[:16])
        self._chunk_type = SCTPType(self._chunk_type)
        self._application_data = self._transport_data[self._chunk_length:]

        if len(self._application_data) == 0:
            return

        self._application_type = ApplicationType(self._src_port)
        if self._application_type != ApplicationType.UNKNOWN:
            return

        self._application_type = ApplicationType(self._dest_port)
        return

    def print_data(self):
        print("SCTP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Verification Tag: {}\n"
              "\t+Checksum: {}\n"
              "\t+Chunk Type: {}\n"
              "\t+Chunk Flags: {}\n"
              "\t+Chunk Length: {}\n"
              "\t+Application Type: {}".format(self._src_port,
                                               self._dest_port,
                                               self._verification_tag,
                                               self._checksum,
                                               self._chunk_type.name,
                                               self._chunk_flags,
                                               self._chunk_length,
                                               self._application_type))
        return

    @property
    def verification_tag(self) -> int:
        return self._verification_tag

    @property
    def checksum(self) -> int:
        return self._checksum

    @property
    def chunk_type(self) -> SCTPType:
        return self._chunk_type

    @property
    def chunk_flags(self) -> int:
        return self._chunk_flags

    @property
    def chunk_length(self) -> int:
        return self._chunk_length
