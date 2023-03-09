from enum import Enum

class PFCPType(Enum):

    # NODE RELATED MESSAGES
    HEARTBEAT_REQUEST = 0x01
    HEARTBEAT_RESPONSE = 0x02
    PFD_MANAGEMENT_REQUEST = 0x03
    PFD_MANAGEMENT_RESPONSE = 0x04
    PFD_ASSOCIATION_SETUP_REQUEST = 0x05
    PFD_ASSOCIATION_SETUP_RESPONSE = 0x06
    PFD_ASSOCIATION_UPDATE_REQUEST = 0x07
    PFD_ASSOCIATION_UPDATE_RESPONSE = 0x08
    PFD_ASSOCIATION_RELEASE_REQUEST = 0x09
    PFD_ASSOCIATION_RELEASE_RESPONSE = 0x0A
    VERSION_NOT_SUPPORTED = 0x0B
    NODE_REPORT_REQUEST = 0x0C
    NODE_REPORT_RESPONSE = 0x0D
    SESSION_SET_DELETION_REQUEST = 0x0E
    SESSION_SET_DELETION_RESPONSE = 0x0F

    # SESSION RELATED MESSAGES
    SESSION_ESTABLISHMENT_REQUEST = 0x32
    SESSION_ESTABLISHMENT_RESPONSE = 0x33
    SESSION_MODIFICATION_REQUEST = 0x34
    SESSION_MODIFICATION_RESPONSE = 0x35
    SESSION_DELETION_REQUEST = 0x36
    SESSION_DELETION_RESPONSE = 0x37
    SESSION_REPORT_REQUEST = 0x38
    SESSION_REPORT_RESPONSE = 0x39

    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN