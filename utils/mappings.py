from enum import Enum


class NetworkType(Enum):
    IPV4 = 0x0800
    ARP = 0x0806
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


class SCTPType(Enum):
    HEARTBEAT = 0x04
    HEARTBEAT_ACK = 0x05
    UNKNOWN = 0x00
    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN

class ApplicationType(Enum):

    HTTP = 80
    HTTPS = 443
    PFCP = 8805
    UNKNOWN = 0

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


