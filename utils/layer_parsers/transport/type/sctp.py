from utils.layer_parsers.transport.transport import TransportLayer
from utils.layer_parsers.application.application import ApplicationType
import struct
from enum import Enum


class SCTPType(Enum):
    HEARTBEAT = 0x04
    HEARTBEAT_ACK = 0x05
    UNKNOWN = 0x00
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
              "\t+Chunk Length: {}".format(self._src_port,
                                           self._dest_port,
                                           self._verification_tag,
                                           self._checksum,
                                           self._chunk_type.name,
                                           self._chunk_flags,
                                           self._chunk_length))
        if self._application_type is not None and len(self._application_data) > 0:
            print("\t+Application Type: {}".format(self._application_type.name))
        return

    @property
    def verification_tag(self):
        return self._verification_tag

    @property
    def checksum(self):
        return self._checksum

    @property
    def chunk_type(self):
        return self._chunk_type

    @property
    def chunk_flags(self):
        return self._chunk_flags

    @property
    def chunk_length(self):
        return self._chunk_length
