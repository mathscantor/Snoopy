from enum import Enum


class NetworkType(Enum):
    IPV4 = 0x0800
    ARP = 0x0806
    IPV6 = 0x86dd
    UNKNOWN = 0xffff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN
