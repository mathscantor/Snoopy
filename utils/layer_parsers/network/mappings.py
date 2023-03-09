from enum import Enum


class TransportType(Enum):
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11
    SCTP = 0x84
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN