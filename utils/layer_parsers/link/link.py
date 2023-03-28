from enum import Enum
from utils.layer_parsers.network.network import NetworkType


class LinkType(Enum):

    ETHER = 0x01
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class LinkLayer:

    def __init__(self, link_type, link_data):
        self._link_type = link_type
        self._link_data = link_data
        self._dest_mac = None
        self._src_mac = None
        self._network_type = None
        self._network_data = None
        return

    def _get_mac_addr(self, raw_mac):
        byte_str = map('{:02x}'.format, raw_mac)
        mac_addr = ':'.join(byte_str).upper()
        return mac_addr

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    def print_raw_data(self):
        if self._network_data is not None and len(self._network_data) > 0:
            print("Link Type: {}".format(self._link_type.name))
            print("Raw Data ({} bytes):".format(len(self._network_data)))
            print(self._network_data)
        return

    @property
    def link_type(self) -> LinkType:
        return self._link_type

    @property
    def link_data(self) -> bytes:
        return self._link_data

    @property
    def dest_mac(self) -> str:
        return self._dest_mac

    @property
    def src_mac(self) -> str:
        return self._src_mac

    @property
    def network_type(self) -> NetworkType:
        return self._network_type

    @property
    def network_data(self) -> bytes:
        return self._network_data
