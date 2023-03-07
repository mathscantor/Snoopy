from enum import Enum


class NetworkType(Enum):
    IPV4 = 0x0800
    IPV6 = 0x86dd
    UNKNOWN = 0xffff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TransportType(Enum):
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11
    SCTP = 0x84
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN

