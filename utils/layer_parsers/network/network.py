from enum import Enum
from utils.layer_parsers.transport.transport import TransportType


class NetworkType(Enum):
    IPV4 = 0x0800
    # ARP = 0x0806  # TODO
    IPV6 = 0x86dd
    UNKNOWN = 0xffff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class NetworkLayer():

    def __init__(self, network_type, network_data):
        self._network_type = network_type

        # Common fields
        self._network_data = network_data
        self._version = None
        self._transport_type = None
        self._transport_data = None
        self._src_ip = None
        self._dst_ip = None

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    def print_raw_data(self):
        if self._network_data is not None and len(self._network_data) > 0:
            print("Network Type: {}".format(self._network_type.name))
            print("Raw Data ({} bytes):".format(len(self._network_data)))
            print(self._network_data)
        return


    @property
    def network_type(self) -> NetworkType:
        return self._network_type

    @property
    def network_data(self) -> bytes:
        return self._network_data

    @property
    def version(self) -> int:
        return self._version

    @property
    def transport_type(self) -> TransportType:
        return self._transport_type

    @property
    def transport_data(self) -> bytes:
        return self._transport_data

    @property
    def src_ip(self) -> str:
        return self._src_ip

    @property
    def dest_ip(self) -> str:
        return self._dest_ip


