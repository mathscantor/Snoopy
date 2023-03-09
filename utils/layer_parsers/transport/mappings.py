from enum import Enum


class ApplicationType(Enum):

    HTTP = 80
    HTTPS = 443
    PFCP = 8805
    UNKNOWN = 0

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