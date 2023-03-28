from enum import Enum
from utils.layer_parsers.application.application import ApplicationType


class TransportType(Enum):
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11
    SCTP = 0x84
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TransportLayer:

    def __init__(self, transport_type, transport_data):

        self._transport_type = transport_type
        self._transport_data = transport_data
        self._application_type = None
        self._application_data = None
        self._src_port = None
        self._dest_port = None
        return

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    def print_raw_data(self):
        if self._transport_data is not None and len(self._transport_data) > 0:
            print("Transport Type: {}".format(self._transport_type.name))
            print("Raw Data ({} bytes):".format(len(self._transport_data)))
            print(self._transport_data)
        return

    def is_padding(self, byte_string):
        for b in byte_string:
            if b != 0:
                return False
        return True

    @property
    def transport_type(self) -> TransportType:
        return self._transport_type

    @property
    def transport_data(self) -> bytes:
        return self._transport_data

    @property
    def application_type(self) -> ApplicationType:
        return self._application_type

    @property
    def application_data(self) -> bytes:
        return self._application_data

    @property
    def src_port(self) -> int:
        return self._src_port

    @property
    def dest_port(self) -> int:
        return self._dest_port


