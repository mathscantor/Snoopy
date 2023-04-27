from utils.layer_parsers.application.application import *
import struct
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from datetime import datetime


class PFCPMessageType(Enum):
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


class IEType(Enum):
    RESERVED = 0
    CREATE_PDR = 1
    PDI = 2
    CREATE_FAR = 3
    FORWARDING_PARAMETERS = 4
    DUPLICATING_PARAMETERS = 5
    CREATE_URR = 6
    CREATE_QER = 7
    CREATED_PDR = 8
    UPDATE_PDR = 9
    UPDATE_FAR = 10
    UPDATE_FORWARDING_PARAMETERS = 11
    UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE = 12
    UPDATE_URR = 13
    UPDATE_QER = 14
    REMOVE_PDR = 15
    REMOVE_FAR = 16
    REMOVE_URR = 17
    REMOVE_QER = 18
    CAUSE = 19
    SOURCE_INTERFACE = 20
    F_TEID = 21
    NETWORK_INSTANCE = 22
    SDF_FILTER = 23
    APPLICATION_ID = 24
    GATE_STATUS = 25
    MBR = 26
    GBR = 27
    QER_CORRELATION_ID = 28
    PRECEDENCE = 29
    TRANSPORT_LEVEL_MARKING = 30
    VOLUME_THRESHOLD = 31
    TIME_THRESHOLD = 32
    MONITORING_TIME = 33
    SUBSEQUENT_VOLUME_THRESHOLD = 34
    SUBSEQUENT_TIME_THRESHOLD = 35
    INACTIVITY_DETECTION_TIME = 36
    REPORTING_TRIGGERS = 37
    REDIRECT_INFORMATION = 38
    REPORT_TYPE = 39
    OFFENDING_IE = 40
    FORWARDING_POLICY = 41
    DESTINATION_INTERFACE = 42
    UP_FUNCTION_FEATURES = 43
    APPLY_ACTION = 44
    DOWNLINK_DATA_SERVICE_INFORMATION = 45
    DOWNLINK_DATA_NOTIFICATION_DELAY = 46
    DL_BUFFERING_DURATION = 47
    DL_BUFFERING_SUGGESTED_PACKET_COUNT = 48
    PFCPSMREQ_FLAGS = 49
    PFCPSRRSP_FLAGS = 50
    LOAD_CONTROL_INFORMATION = 51
    SEQUENCE_NUMBER = 52
    METRIC = 53
    OVERLOAD_CONTROL_INFORMATION = 54
    TIMER = 55
    PDR_ID = 56
    F_SEID = 57
    APPLICATION_IDS_PFDS = 58
    PFD_CONTEXT = 59
    NODE_ID = 60
    PFD_CONTENTS = 61
    MEASUREMENT_METHOD = 62
    USAGE_REPORT_TRIGGER = 63
    MEASUREMENT_PERIOD = 64
    FQ_CSID = 65
    VOLUME_MEASUREMENT = 66
    DURATION_MEASUREMENT = 67
    APPLICATION_DETECTION_INFORMATION = 68
    TIME_OF_FIRST_PACKET = 69
    TIME_OF_LAST_PACKET = 70
    QUOTA_HOLDING_TIME = 71
    DROPPED_DL_TRAFFIC_THRESHOLD = 72
    VOLUME_QUOTA = 73
    TIME_QUOTA = 74
    START_TIME = 75
    END_TIME = 76
    QUERY_URR = 77
    USAGE_REPORT_SESSION_MODIFICATION_RESPONSE = 78
    USAGE_REPORT_SESSION_DELETION_RESPONSE = 79
    USAGE_REPORT_SESSION_REPORT_REQUEST = 80
    URR_ID = 81
    LINKED_URR_ID = 82
    DOWNLINK_DATA_REPORT = 83
    OUTER_HEADER_CREATION = 84
    CREATE_BAR = 85
    UPDATE_BAR = 86
    REMOVE_BAR = 87
    BAR_ID = 88
    CP_FUNCTION_FEATURES = 89
    USAGE_INFORMATION = 90
    APPLICATION_INSTANCE_ID = 91
    FLOW_INFORMATION = 92
    UE_IP_ADDRESS = 93
    PACKET_RATE = 94
    OUTER_HEADER_REMOVAL = 95
    RECOVERY_TIME_STAMP = 96
    DL_FLOW_LEVEL_MARKING = 97
    HEADER_ENRICHMENT = 98
    ERROR_INDICATION_REPORT = 99
    MEASUREMENT_INFORMATION = 100
    NODE_REPORT_TYPE = 101
    USER_PLANE_PATH_FAILURE_REPORT = 102
    REMOTE_GTPU_PEER = 103
    UR_SEQN = 104
    UPDATE_DUPLICATING_PARAMETERS = 105
    ACTIVATE_PREDEFINED_RULES = 106
    DEACTIVATE_PREDEFINED_RULES = 107
    FAR_ID = 108
    QER_ID = 109
    OCI_FLAGS = 110
    PFCP_ASSOCIATION_RELEASE_REQUEST = 111
    GRACEFUL_RELEASE_PERIOD = 112
    PDN_TYPE = 113
    FAILED_RULE_ID = 114
    TIME_QUOTA_MECHANISM = 115
    USER_PLANE_IP_RESOURCE_INFORMATION = 116
    USER_PLANE_INACTIVITY_TIMER = 117
    AGGREGATED_URRS = 118
    MULTIPLIER = 119
    AGGREGATED_URR_ID = 120
    SUBSEQUENT_VOLUME_QUOTA = 121
    SUBSEQUENT_TIME_QUOTA = 122
    RQI = 123
    QFI = 124
    QUERY_URR_REFERENCE = 125
    ADDITIONAL_USAGE_REPORTS_INFORMATION = 126
    CREATE_TRAFFIC_ENDPOINT = 127
    CREATED_TRAFFIC_ENDPOINT = 128
    UPDATE_TRAFFIC_ENDPOINT = 129
    REMOVE_TRAFFIC_ENDPOINT = 130
    TRAFFIC_ENDPOINT_ID = 131
    ETHERNET_PACKET_FILTER = 132
    MAC_ADDRESS = 133
    C_TAG = 134
    S_TAG = 135
    ETHERTYPE = 136
    PROXYING = 137
    ETHERNET_FILTER_ID = 138
    ETHERNET_FILTER_PROPERTIES = 139
    SUGGESTED_BUFFERING_PACKETS_COUNT = 140
    USER_ID = 141
    ETHERNET_PDU_SESSION_INFORMATION = 142
    ETHERNET_TRAFFIC_INFORMATION = 143
    MAC_ADDRESSES_DETECTED = 144
    MAC_ADDRESSES_REMOVED = 145
    ETHERNET_INACTIVITY_TIMER = 146
    ADDITIONAL_MONITORING_TIME = 147
    EVENT_QUOTA = 148
    EVENT_THRESHOLD = 149
    SUBSEQUENT_EVENT_QUOTA = 150
    SUBSEQUENT_EVENT_THRESHOLD = 151
    TRACE_INFORMATION = 152
    FRAMED_ROUTE = 153
    FRAMED_ROUTING = 154
    FRAMED_IPV6_ROUTE = 155
    EVENT_TIME_STAMP = 156
    AVERAGING_WINDOW = 157
    PAGING_POLICY_INDICATOR = 158
    APN_DNN = 159
    THREE_GPP_INTERFACE_TYPE = 160
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class CauseValuesType(Enum):
    RESERVED = 0
    REQUEST_ACCEPTED = 1
    REQUEST_REJECTED = 64
    SESSION_CONTEXT_NOT_FOUND = 65
    MANDATORY_IE_MISSING = 66
    CONDITIONAL_IE_MISSING = 67
    INVALID_LENGTH = 68
    MANDATORY_IE_INCORRECT = 69
    INVALID_FORWARDING_POLICY = 70
    INVALID_F_TEID_ALLOCATION_OPTION = 71
    NO_ESTABLISHED_SX_ASSOCIATION = 72
    RULE_CREATION_MODIFICATION_FAILURE = 73
    PFCP_ENTITY_IN_CONGESTION = 74
    NO_RESOURCES_AVAILABLE = 75
    SERVICE_NOT_SUPPORTED = 76
    SYSTEM_FAILURE = 77
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class SourceInterfaceType(Enum):
    ACCESS = 0  # uplink traffic (from ue to network)
    CORE = 1    # downlink traffic (from network to ue)
    SGI_LAN_N6_LAN = 2
    CP_FUNCTION = 3
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class DestinationInterfaceType(Enum):
    ACCESS = 0  # downlink traffic (from network to ue)
    CORE = 1    # uplink traffic(from ue to network)
    SGI_LAN_N6_LAN = 2
    CP_FUNCTION = 3
    LI_FUNCTION = 4
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class RedirectAddressType(Enum):
    IPV4_ADDRESS = 0
    IPV6_ADDRESS = 1
    URL = 2
    SIP_URI = 3
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class GateStatusType(Enum):
    OPEN = 0
    CLOSED = 1
    CLOSED_RESERVED_2 = 2
    CLOSED_RESERVED_3 = 3
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TimerUnitType(Enum):
    TWO_SECONDS = 0
    ONE_MINUTE = 1
    TEN_MINUTES = 2
    ONE_HOUR = 3
    TEN_HOURS = 4
    INFINITE = 7
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class OuterHeaderRemovalDescriptionType(Enum):
    GTP_U_UDP_IPV4 = 0
    GTP_U_UDP_IPV6 = 1
    UDP_IPV4 = 2
    UDP_IPV6 = 3
    IPV4 = 4
    IPV6 = 5
    GTP_U_UDP_IP = 6
    VLAN_S_TAG = 7
    S_TAG_AND_C_TAG = 8
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class NodeIdType(Enum):
    IPV4 = 0
    IPV6 = 1
    FQDN = 2
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class FqCSIDNodeIdType(Enum):
    IPV4 = 0
    IPV6 = 1
    MCCMNC_ID = 2
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class FlowDirectionType(Enum):
    UNSPECIFIED = 0
    DOWNLINK = 1  # traffic to the UE
    UPLINK = 2  # traffic from the UE
    BIDIRECTIONAL = 3
    UNSPECIFIED4 = 4
    UNSPECIFIED5 = 5
    UNSPECIFIED6 = 6
    UNSPECIFIED7 = 7
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TimeUnitType(Enum):
    MINUTE = 0
    MIN6 = 1
    HOUR = 2
    DAY = 3
    WEEK = 4
    MIN5 = 5  # same as 0 (minute)
    MIN7 = 6  # same as 0 (minute)
    MIN8 = 7  # same as 0 (minute)
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class HeaderType(Enum):
    HTTP = 0
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class PDNType(Enum):
    IPV4 = 0
    IPV6 = 1
    IPV4V6 = 2
    NON_IP = 3
    ETHERNET = 4
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class RuleIDType(Enum):
    PDR = 0
    FAR = 1
    QER = 2
    URR = 3
    BAR = 4
    UNKNOWN = 0xFF

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class BaseTimeIntervalType(Enum):
    CTP = 0
    DTP = 1
    UNKNOWN = 0xFF

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class InterfaceType(Enum):
    S1_U = 0
    S5_S8_U = 1
    S4_U = 2
    S11_U = 3
    S12_U = 4
    GN_GP_U = 5
    S2A_U = 6
    S2B_U = 7
    ENODEB_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING = 8
    ENODEB_GTP_U_INTERFACE_FOR_UL_DATA_FORWARDING = 9
    SGW_UPF_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING = 10
    N3_3GPP_ACCESS = 11
    N3_TRUSTED_NON_3GPP_ACCESS = 12
    N3_UNTRUSTED_NON_3GPP_ACCESS = 13
    N3_FOR_DATA_FORWARDING = 14
    N9 = 15
    UNKNOWN = 0xFF

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class IE:

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        self._ie_type = IEType.UNKNOWN
        self._ie_length = ie_length
        self._ie_payload = ie_payload
        self._ie_list = None # Only relevant to Grouped IEs

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def _parse_grouped_data(self):
        greedy_payload = self._ie_payload
        if len(greedy_payload) == 0:
            return
        else:
            self._ie_list = []
        while len(greedy_payload) > 0:
            # First 4 bytes -- IE Type (2 bytes) and IE Length (2 bytes)
            ie_type_int, ie_length = struct.unpack('! H H', greedy_payload[0:4])
            ie_type = IEType(ie_type_int)
            ie_obj = select_ie(ie_type=ie_type, ie_length=ie_length, ie_payload=greedy_payload[4: 4 + ie_length])
            if ie_obj is not None:
                self._ie_list.append(ie_obj)
            greedy_payload = greedy_payload[4 + ie_length:]
        return

    def print_data(self):
        self._print_init()
        self._print_ie_list()
        pass

    def _print_init(self):
        # To be overwritten by child class
        return

    def _print_ie_list(self):
        if self._ie_list is None:
            return

        if len(self._ie_list) == 0:
            return

        for ie_obj in self._ie_list:
            ie_obj.print_data()
        return

    @property
    def ie_type(self) -> IEType:
        return self._ie_type

    @property
    def ie_length(self) -> int:
        return self._ie_length

    @property
    def ie_payload(self) -> bytes:
        return self._ie_payload

    @property
    def ie_list(self) -> list:
        return self._ie_list


class IE_RecoveryTimeStamp(IE):
    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.RECOVERY_TIME_STAMP
        self._recovery_timestamp_epoch = None
        self._recovery_timestamp_datetime = None
        self._parse_data()

    def _parse_data(self):
        # Magic Number
        self._recovery_timestamp_epoch = struct.unpack('! L', self._ie_payload[0: self._ie_length])[0] - 2208988800
        self._recovery_timestamp_datetime = datetime.utcfromtimestamp(self._recovery_timestamp_epoch)
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}\n"
              "\t+Recovery Timestamp:\n"
              "\t\t+Epoch: {}\n"
              "\t\t+Datetime: {} UTC".format(self._ie_type.name, self._ie_length,
                                             self._recovery_timestamp_epoch,
                                             self._recovery_timestamp_datetime.strftime('%d-%m-%Y %H:%M:%S')))
        return

    @property
    def recovery_timestamp_epoch(self) -> int:
        return self._recovery_timestamp_epoch

    @property
    def recovery_timestamp_datetime(self) -> datetime:
        return self._recovery_timestamp_datetime


class IE_NodeId(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.NODE_ID

        self._spare = None
        self._nodeid_type = None
        self._node_ip = None
        self._parse_data()

    def _parse_data(self):
        self._spare = self._ie_payload[0] >> 4
        self._nodeid_type = NodeIdType(self._ie_payload[0] & 0x0f)

        if self._nodeid_type == NodeIdType.IPV4:
            self._node_ip = str(IPv4Address(self._ie_payload[1:self._ie_length]))
        elif self._nodeid_type == NodeIdType.IPV6:
            self._node_ip = str(IPv6Address(self._ie_payload[1:self._ie_length]))
        elif self._nodeid_type == NodeIdType.FQDN:
            self._node_ip = self.__convert_raw_bytes_to_fqdn(self._ie_payload[1:self._ie_length])
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}\n"
              "\t+Spare: {}, Address Type: {}\n"
              "\t+Address: {}".format(self._ie_type.name, self._ie_length,
                                      self._spare, self._nodeid_type.name,
                                      self._node_ip))
        return

    def __convert_raw_bytes_to_fqdn(self, raw_bytes) -> str:

        # Split the raw bytes into labels
        labels = []
        i = 0
        while i < len(raw_bytes):
            label_len = raw_bytes[i]
            if label_len == 0:
                break
            label = raw_bytes[i + 1:i + 1 + label_len].decode('utf-8')
            labels.append(label)
            i += 1 + label_len

        # Join the labels to form the domain name
        domain_name = '.'.join(labels)

        return domain_name

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def nodeid_type(self) -> NodeIdType:
        return self._nodeid_type

    @property
    def node_ip(self) -> str:
        return self._node_ip


class IE_FSEID(IE):
    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.F_SEID

        self._spare1 = None
        self._spare2 = None
        self._spare3 = None
        self._spare4 = None
        self._spare5 = None
        self._spare6 = None
        self._ipv4_flag = None
        self._ipv6_flag = None
        self._seid = None
        self._ipv4_address = None
        self._ipv6_address = None
        self._parse_data()

    def _parse_data(self):
        self._spare1 = (self._ie_payload[0] >> 7) & 0x1
        self._spare2 = (self._ie_payload[0] >> 6) & 0x1
        self._spare3 = (self._ie_payload[0] >> 5) & 0x1
        self._spare4 = (self._ie_payload[0] >> 4) & 0x1
        self._spare5 = (self._ie_payload[0] >> 3) & 0x1
        self._spare6 = (self._ie_payload[0] >> 2) & 0x1
        self._ipv4_flag = (self._ie_payload[0] >> 1) & 0x1
        self._ipv6_flag = self._ie_payload[0] & 0x1

        limit = 9
        self._seid = int.from_bytes(self._ie_payload[1:limit], 'big')
        if self._ipv4_flag == 1:
            self._ipv4_address = str(IPv4Address(self._ie_payload[limit: limit+4]))
            limit += 4
        if self._ipv6_flag == 1:
            self._ipv6_address = str(IPv6Address(self._ie_payload[limit: limit+16]))

        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}\n"
              "\t+Spare1: {}\n"
              "\t+Spare2: {}\n"
              "\t+Spare3: {}\n,"
              "\t+Spare4: {}\n,"
              "\t+Spare5: {}\n,"
              "\t+Spare6: {}\n,"
              "\t+IPv4 Flag: {}\n"
              "\t+IPv6 Flag: {}\n"
              "\t+SEID: {}\n"
              "\t+IPv4 Address: {}\n"
              "\t+IPv6 Address: {}".format(self._ie_type.name, self._ie_length,
                                           self._spare1, self._spare2, self._spare3, self._spare4, self.spare5,
                                           self.spare6, self._ipv4_flag, self._ipv6_flag, self._seid,
                                           self._ipv4_address, self._ipv6_address))
        return

    @property
    def spare1(self) -> int:
        return self._spare1

    @property
    def spare2(self) -> int:
        return self._spare2

    @property
    def spare3(self) -> int:
        return self._spare3

    @property
    def spare4(self) -> int:
        return self._spare4

    @property
    def spare5(self) -> int:
        return self._spare5

    @property
    def spare6(self) -> int:
        return self._spare6

    @property
    def ipv4_flag(self) -> int:
        return self._ipv4_flag

    @property
    def ipv6_flag(self) -> int:
        return self._ipv6_flag

    @property
    def seid(self) -> int:
        return self._seid

    @property
    def ipv4_address(self) -> str:
        return self._ipv4_address

    @property
    def ipv6_address(self) -> str:
        return self._ipv6_address


class IE_CreatePDR(IE):
    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.CREATE_PDR

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}".format(IEType.CREATE_PDR.name, self._ie_length))
        return


class IE_CreatedPDR(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.CREATED_PDR

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


class IE_CreateFAR(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.CREATE_FAR

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


class IE_CreateURR(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.CREATE_URR

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


class IE_PDR_ID(IE):
    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.PDR_ID

        self._id = None
        self._parse_data()

    def _parse_data(self):
        self._id = struct.unpack('! H', self._ie_payload[0: self._ie_length])[0]
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+PDR ID: {}".format(IEType.PDR_ID.name, self._ie_length,
                                       self._id))
        return

    @property
    def id(self) -> int:
        return self._id


class IE_FAR_ID(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.FAR_ID

        self._id = None
        self._parse_data()

    def _parse_data(self):
        self._id = int.from_bytes(self._ie_payload[0:self._ie_length], 'big') & 0x7fff
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+FAR ID: {}".format(self._ie_type.name, self._ie_length,
                                       self._id))
        return

    @property
    def id(self) -> int:
        return self._id


class IE_QER_ID(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.QER_ID

        self._id = None
        self._parse_data()

    def _parse_data(self):
        self._id = int.from_bytes(self._ie_payload[0:self._ie_length], 'big') & 0x7fff
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+QER ID: {}".format(self._ie_type.name, self._ie_length,
                                       self._id))
        return

    @property
    def id(self) -> int:
        return self._id


class IE_BAR_ID(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.BAR_ID

        self._id = None
        self._parse_data()

    def _parse_data(self):
        self._id = int.from_bytes(self._ie_payload[0:self._ie_length], 'big') & 0x7fff
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+BAR ID: {}".format(self._ie_type.name, self._ie_length,
                                       self._id))
        return

    @property
    def id(self) -> int:
        return self._id


class IE_URR_ID(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.URR_ID

        self._id = None
        self._parse_data()

    def _parse_data(self):
        self._id = int.from_bytes(self._ie_payload[0:self._ie_length], 'big') & 0x7fff
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+URR ID: {}".format(self._ie_type.name, self._ie_length,
                                       self._id))
        return

    @property
    def id(self) -> int:
        return self._id


class IE_Precedence(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.PRECEDENCE

        self._precedence = None
        self._parse_data()

    def _parse_data(self):
        self._precedence = struct.unpack('! L', self._ie_payload[0: self._ie_length])[0]
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+Precedence: {}".format(IEType.PRECEDENCE.name, self._ie_length,
                                           self._precedence))
        return

    @property
    def precedence(self) -> int:
        return self._precedence


class IE_PDI(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.PDI

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


class IE_SourceInterface(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.SOURCE_INTERFACE

        self._spare = None
        self._source_interface_type = None
        self._parse_data()

    def _parse_data(self):
        self._spare = self._ie_payload[0] >> 4
        self._source_interface_type = SourceInterfaceType(self._ie_payload[0] & 0x0f)
        return

    def _print_init(self):
        print("\t\tIE Type: {}, IE Length: {}\n"
              "\t\t\t+Spare: {}\n"
              "\t\t\t+Source Interface Type: {}".format(self._ie_type.name, self._ie_length,
                                                        self._spare,
                                                        self._source_interface_type.name))
        return

    @property
    def source_interface_type(self) -> SourceInterfaceType:
        return self._source_interface_type

    @property
    def spare(self) -> int:
        return self._spare


class IE_NetworkInstance(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.NETWORK_INSTANCE

        self._network_instance = None
        self._parse_data()

    def _parse_data(self):
        # Ignore the first byte as 0x08 represents a field tag
        # The remaining bytes represents our actual string.
        self._network_instance = self._ie_payload[1: self._ie_length].decode('utf-8')
        return

    def _print_init(self):
        print("\t\tIE Type: {}, IE Length: {}\n"
              "\t\t\t+Network Instance: {}".format(self._ie_type.name, self._ie_length,
                                                   self._network_instance))
        return

    @property
    def network_instance(self) -> str:
        return self._network_instance


class IE_FTEID(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.F_TEID

        self._spare = None
        self._choose_id_flag = None
        self._choose_flag = None
        self._ipv6_present_flag = None
        self._ipv4_present_flag = None
        self._choose_id = None
        self._teid = None
        self._ipv6_address = None
        self._ipv4_address = None
        self._parse_data()

    def _parse_data(self):
        self._spare = self._ie_payload[0] >> 4
        self._choose_id_flag = (self._ie_payload[0] >> 3) & 0x1
        self._choose_flag = (self._ie_payload[0] >> 2) & 0x1
        self._ipv6_present_flag = (self._ie_payload[0] >> 1) & 0x1
        self._ipv4_present_flag = self._ie_payload[0] & 0x1

        # Only for pfcp session establishment requests
        if self._choose_id_flag == 1:
            self._choose_id = self._ie_payload[1]

        if self._choose_flag == 1:
            return

        # Only for pfcp session establishment responses
        self._teid = struct.unpack('! L', self._ie_payload[1:5])[0]
        if self._ipv6_present_flag == 1:
            self._ipv6_address = str(IPv6Address(self._ie_payload[5:21]))
            if self._ipv4_present_flag == 1:
                self._ipv4_address = str(IPv4Address(self._ie_payload[21:25]))
            return

        if self._ipv4_present_flag == 1:
            self._ipv4_address = str(IPv4Address(self._ie_payload[5:9]))
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+Spare: {}\n"
              "\t\t+Choose ID Flag: {}\n"
              "\t\t+Choose Flag: {}\n"
              "\t\t+IPv6 Present Flag: {}\n"
              "\t\t+IPv4 Present Flag: {}".format(self._ie_type.name, self._ie_length,
                                                  self._spare,
                                                  self._choose_id_flag,
                                                  self._choose_flag,
                                                  self._ipv6_present_flag,
                                                  self._ipv4_present_flag))
        if self._choose_id is not None:
            print("\t\t+Choose ID: {}".format(self._choose_id))
        if self._teid is not None:
            print("\t\t+TEID: {}".format(self._teid))
        if self._ipv6_address is not None:
            print("\t\t+IPv6 Address: {}".format(self._ipv6_address))
        if self._ipv4_address is not None:
            print("\t\t+IPv4 Address: {}".format(self._ipv4_address))
        return

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def choose_id_flag(self) -> int:
        return self._choose_id_flag

    @property
    def choose_flag(self) -> int:
        return self._choose_flag

    @property
    def ipv6_present_flag(self) -> int:
        return self._ipv6_present_flag

    @property
    def ipv4_present_flag(self) -> int:
        return self._ipv4_present_flag

    @property
    def choose_id(self) -> int:
        return self._choose_id

    @property
    def teid(self) -> int:
        return self._teid

    @property
    def ipv6_address(self) -> str:
        return self._ipv6_address

    @property
    def ipv4_address(self) -> str:
        return self._ipv4_address


class IE_UE_IP_Address(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.UE_IP_ADDRESS

        self._spare = None
        self._ipv6pl_flag = None
        self._chv6_flag = None
        self._chv4_flag = None
        self._ipv6d_flag = None
        self._sd_flag = None
        self._ipv4_present_flag = None
        self._ipv6_present_flag = None
        self._ipv4_address = None
        self._ipv6_address = None
        self._parse_data()

    def _parse_data(self):
        self._spare = (self._ie_payload[0] >> 7) & 0x1
        self._ipv6pl_flag = (self._ie_payload[0] >> 6) & 0x1
        self._chv6_flag = (self._ie_payload[0] >> 5) & 0x1
        self._chv4_flag = (self._ie_payload[0] >> 4) & 0x1
        self._ipv6d_flag = (self._ie_payload[0] >> 3) & 0x1
        self._sd_flag = (self._ie_payload[0] >> 2) & 0x1
        self._ipv4_present_flag = (self._ie_payload[0] >> 1) & 0x1
        self._ipv6_present_flag = self._ie_payload[0] & 0x1

        if self._ipv4_present_flag == 1:
            self._ipv4_address = str(IPv4Address(self._ie_payload[1:5]))
            if self._ipv6_present_flag == 1:
                self._ipv6_address = str(IPv6Address(self._ie_payload[5:21]))
                return

        if self._ipv6_present_flag == 1:
            self._ipv6_address = str(IPv6Address(self._ie_payload[1:17]))
        return

    def _print_init(self):
        print("\t\tIE Type: {}, IE Length: {}\n"
              "\t\t\t+Spare: {}\n"
              "\t\t\t+IPV6PL: {}\n"
              "\t\t\t+CHV6: {}\n"
              "\t\t\t+CHV4: {}\n"
              "\t\t\t+IPv6D: {}\n"
              "\t\t\t+S/D: {}\n"
              "\t\t\t+IPv4 Present: {}\n"
              "\t\t\t+IPv6 Present: {}".format(self._ie_type.name, self._ie_length,
                                               self._spare,
                                               self._ipv6pl_flag,
                                               self._chv6_flag,
                                               self._chv4_flag,
                                               self._ipv6d_flag,
                                               self._sd_flag,
                                               self._ipv4_present_flag,
                                               self._ipv6_present_flag))

        if self._ipv4_address is not None:
            print("\t\t\t+IPv4 Address: {}".format(self._ipv4_address))
        if self._ipv6_address is not None:
            print("\t\t\t+IPv6 Address: {}".format(self._ipv6_address))
        return

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def ipv6pl_flag(self) -> int:
        return self._ipv6pl_flag

    @property
    def chv6_flag(self) -> int:
        return self._chv6_flag

    @property
    def chv4_flag(self) -> int:
        return self._chv4_flag

    @property
    def ipv6d_flag(self) -> int:
        return self._ipv6d_flag

    @property
    def sd_flag(self) -> int:
        return self._sd_flag

    @property
    def ipv4_present_flag(self):
        return self._ipv4_present_flag

    @property
    def ipv6_present_flag(self):
        return self._ipv6_present_flag

    @property
    def ipv4_address(self) -> int:
        return self._ipv4_address

    @property
    def ipv6_address(self) -> int:
        return self._ipv6_address


class IE_QFI(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.QFI

        self._spare = None
        self._qfi = None
        self._parse_data()

    def _parse_data(self):
        self._spare = self._ie_payload[0] >> 6
        self._qfi = self._ie_payload[0] & 0x7f
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\t+Spare: {}\n"
              "\t\t+QFI: {}".format(self._ie_type.name, self._ie_length,
                                    self._spare,
                                    self._qfi))
        return

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def qfi(self) -> int:
        return self._qfi


class IE_OuterHeaderRemoval(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.OUTER_HEADER_REMOVAL

        self._outer_header_removal_description_type = None
        self._pdu_session_container_delete_flag = None
        self._parse_data()

    def _parse_data(self):
        self._outer_header_removal_description_type = OuterHeaderRemovalDescriptionType(self._ie_payload[0])
        if self._ie_length == 2:
            self._pdu_session_container_delete_flag = self._ie_payload[1]
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}\n"
              "\t\tOuter Header Removal Description: {}".format(self._ie_type.name, self._ie_length,
                                                            self._outer_header_removal_description_type.name))
        if self._pdu_session_container_delete_flag is not None:
            print("PDU Session Container to be deleted flag: {}".format(self._pdu_session_container_delete_flag))
        return

    @property
    def outer_header_removal_description_type(self) -> OuterHeaderRemovalDescriptionType:
        return self._outer_header_removal_description_type

    @property
    def pdu_session_container_delete_flag(self) -> int:
        return self._pdu_session_container_delete_flag


class IE_ApplyAction(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.APPLY_ACTION

        #1st byte
        self._dfrt = None   # Duplicate for Redundant Transmission
        self._ipmd = None   # IP Multicast Deny
        self._ipma = None   # IP Multicast Accept
        self._dupl = None   # Duplicate
        self._nocp = None   # Notify the CP function
        self._buff = None   # Buffer
        self._forw = None   # Forward
        self._drop = None   # Drop
        # 2nd byte
        if len(self._ie_payload) == 2:
            self._spare = None  # Spare
            self._mbsu = None   # Forward and replicate MBS data using Unicast transport
            self._fssm = None   # Forward packets to lower layer SSM
            self._ddpn = None   # Discard Downlink Packet Notification
            self._bdpn = None   # Buffered Downlink Packet Notification
            self._edrt = None   # Eliminate Duplicate Packets for Redundant Transmission
        self._parse_data()

    def _parse_data(self):
        self._dfrt = (self._ie_payload[0] >> 7) & 0x1
        self._ipmd = (self._ie_payload[0] >> 6) & 0x1
        self._ipma = (self._ie_payload[0] >> 5) & 0x1
        self._dupl = (self._ie_payload[0] >> 4) & 0x1
        self._nocp = (self._ie_payload[0] >> 3) & 0x1
        self._buff = (self._ie_payload[0] >> 2) & 0x1
        self._forw = (self._ie_payload[0] >> 1) & 0x1
        self._drop = self._ie_payload[0] & 0x1

        self._spare = (self._ie_payload[1] >> 5) & 0x1
        self._mbsu = (self._ie_payload[1] >> 4) & 0x1
        self._fssm = (self._ie_payload[1] >> 3) & 0x1
        self._ddpn = (self._ie_payload[1] >> 2) & 0x1
        self._bdpn = (self._ie_payload[1] >> 1) & 0x1
        self._edrt = self._ie_payload[1] & 0x1
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


    @property
    def dfrt(self) -> int:
        return self._dfrt

    @property
    def ipmd(self) -> int:
        return self._ipmd

    @property
    def ipma(self) -> int:
        return self._ipma

    @property
    def dupl(self) -> int:
        return self._dupl

    @property
    def nocp(self) -> int:
        return self._nocp

    @property
    def buff(self) -> int:
        return self._buff

    @property
    def forw(self) -> int:
        return self._forw

    @property
    def drop(self) -> int:
        return self._drop

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def mbsu(self) -> int:
        return self._mbsu

    @property
    def fssm(self) -> int:
        return self._fssm

    @property
    def ddpn(self) -> int:
        return self._ddpn

    @property
    def bdpn(self) -> int:
        return self._bdpn

    @property
    def edrt(self) -> int:
        return self._edrt


class IE_ForwardingParameters(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.FORWARDING_PARAMETERS

        self._parse_data()

    def _parse_data(self):
        self._parse_grouped_data()
        return

    def _print_init(self):
        print("\tIE Type: {}, IE Length: {}".format(self._ie_type.name, self._ie_length))
        return


class IE_DestinationInterface(IE):

    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.DESTINATION_INTERFACE
        assert ie_length == 1

        self._spare = None
        self._interface_type = None
        self._parse_data()

    def _parse_data(self):
        self._spare = (self._ie_payload[0] >> 4) * 0xf
        self._interface_type = DestinationInterfaceType(self._ie_payload[0] & 0xf)
        return

    def _print_init(self):
        print("\t\tIE Type: {}, IE Length: {}\n"
              "\t\t\t+Spare: {}\n"
              "\t\t\t+Interface: {}".format(self._ie_type.name, self._ie_length,
                                            self._spare,
                                            self._interface_type.name))
        return

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def interface_type(self) -> DestinationInterfaceType:
        return self._interface_type


class PFCP(ApplicationLayer):

    def __init__(self,
                 application_type: ApplicationType,
                 application_data: bytes,
                 src_port: int,
                 dest_port: int):
        ApplicationLayer.__init__(self, application_type, application_data, src_port, dest_port)
        self._flags = None
        self._flag_version = None
        self._flag_spare1 = None
        self._flag_spare2 = None
        self._flag_follow_on = None
        self._flag_message_priority = None
        self._flag_seid = None
        self._message_type = None
        self._length = None
        self._seid = None
        self._sequence_number = None
        self._message = None
        self._spare = None
        self._ie_list = None
        self._parse_data()

    def _parse_data(self):
        self._flags = self._application_data[0]
        self._flag_version = self._flags >> 5                   # xxx. ....
        self._flag_spare1 = (self._flags >> 4) & 0x1            # ...x ....
        self._flag_spare2 = (self._flags >> 3) & 0x1            # .... x...
        self._flag_follow_on = (self._flags >> 2) & 0x1         # .... .x..
        self._flag_message_priority = (self._flags >> 1) & 0x1  # .... ..x.
        self._flag_seid = self._flags & 0x1                     # .... ...x

        if self._flag_seid == 1:
            if self._flag_message_priority == 0:
                self._message_type, self._length, \
                    self._seid, self._sequence_number, \
                    self._spare = struct.unpack('! B H Q 3s B', self._application_data[1:16])
            else:
                self._message_type, self._length, \
                    self._seid, self._sequence_number, \
                    self._message = struct.unpack('! B H Q 3s B', self._application_data[1:16])
            greedy_payload = self._application_data[16:]
        else:
            if self._flag_message_priority == 0:
                self._message_type, self._length, \
                    self._sequence_number, self._spare = struct.unpack('! B H 3s B',
                                                                       self._application_data[1:8])
            else:
                self._message_type, self._length, \
                    self._sequence_number, self._message = struct.unpack('! B H 3s B',
                                                                         self._application_data[1:8])
            greedy_payload = self._application_data[8:]

        self._message_type = PFCPMessageType(self._message_type)
        self._sequence_number = int.from_bytes(self._sequence_number, 'big')

        if len(greedy_payload) == 0:
            return
        else:
            self._ie_list = []

        # Parse greedy payload here into their individual IEs
        # Loop until length reaches 0
        while len(greedy_payload) > 0:
            # First 4 bytes -- IE Type (2 bytes) and IE Length (2 bytes)
            ie_type_int, ie_length = struct.unpack('! H H', greedy_payload[0:4])
            ie_type = IEType(ie_type_int)
            ie_obj = select_ie(ie_type=ie_type, ie_length=ie_length, ie_payload=greedy_payload[4: 4 + ie_length])
            if ie_obj is not None:
                self._ie_list.append(ie_obj)
            greedy_payload = greedy_payload[4+ie_length:]

        return


    def print_data(self):
        self._print_pfcp_init()
        self._print_ie_list()
        return

    def _print_pfcp_init(self):
        print("PFCP Data:")
        print("\t+Flags: {}\n"
              "\t+Message Type: {}\n"
              "\t+Length: {}\n"
              "\t+SEID: {}\n"
              "\t+Sequence Number: {}\n"
              "\t+Spare: {}".format(self._flags,
                                    self._message_type.name,
                                    self._length,
                                    self._seid if self._seid is not None else None,
                                    self._sequence_number,
                                    self._spare))
        return

    def _print_ie_list(self):

        if self._ie_list is None:
            return

        if len(self._ie_list) == 0:
            return

        for ie_obj in self._ie_list:
            ie_obj.print_data()
        return

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def flag_version(self) -> int:
        return self._flag_version

    @property
    def flag_spare1(self) -> int:
        return self._flag_spare1

    @property
    def flag_spare2(self) -> int:
        return self._flag_spare2

    @property
    def flag_follow_on(self) -> int:
        return self._flag_follow_on

    def flag_message_priority(self) -> int:
        return self._flag_message_priority

    @property
    def flag_seid(self) -> int:
        return self._flag_seid

    @property
    def message_type(self) -> PFCPMessageType:
        return self._message_type

    @property
    def length(self) -> int:
        return self._length

    @property
    def seid(self) -> int:
        return self._seid

    @property
    def sequence_number(self) -> int:
        return self._sequence_number

    @property
    def message(self) -> bytes:
        return self._message

    @property
    def spare(self) -> int:
        return self._spare

    @property
    def ie_list(self) -> list:
        return self._ie_list


class IE_Cause(IE):
    def __init__(self,
                 ie_length: int,
                 ie_payload: bytes):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.CAUSE

        assert ie_length == 1
        self._cause_type = None
        self._parse_data()

    def _parse_data(self):
        cause_int = struct.unpack('! B', self._ie_payload[0:self._ie_length])[0]
        self._cause_type = CauseValuesType(cause_int)
        return

    def _print_init(self):
        print("IE Type: {}, IE Length: {}\n"
              "\t+Cause: {}".format(self._ie_type.name, self._ie_length,
                                    self._cause_type.name))
        return

    @property
    def cause_type(self) -> CauseValuesType:
        return self._cause_type


# TODO: Account for other IE classes
def select_ie(ie_type: IEType,
              ie_length: int,
              ie_payload: bytes) -> IE:

    if ie_type == IEType.NODE_ID:
        return IE_NodeId(ie_length, ie_payload)
    elif ie_type == IEType.F_SEID:
        return IE_FSEID(ie_length, ie_payload)
    elif ie_type == IEType.CAUSE:
        return IE_Cause(ie_length, ie_payload)
    elif ie_type == IEType.RECOVERY_TIME_STAMP:
        return IE_RecoveryTimeStamp(ie_length, ie_payload)
    elif ie_type == IEType.CREATE_PDR:
        return IE_CreatePDR(ie_length, ie_payload)
    elif ie_type == IEType.CREATED_PDR:
        return IE_CreatedPDR(ie_length, ie_payload)
    elif ie_type == IEType.CREATE_FAR:
        return IE_CreateFAR(ie_length, ie_payload)
    elif ie_type == IEType.CREATE_URR:
        return IE_CreateURR(ie_length, ie_payload)
    elif ie_type == IEType.PDR_ID:
        return IE_PDR_ID(ie_length, ie_payload)
    elif ie_type == IEType.FAR_ID:
        return IE_FAR_ID(ie_length, ie_payload)
    elif ie_type == IEType.QER_ID:
        return IE_QER_ID(ie_length, ie_payload)
    elif ie_type == IEType.BAR_ID:
        return IE_BAR_ID(ie_length, ie_payload)
    elif ie_type == IEType.URR_ID:
        return IE_URR_ID(ie_length, ie_payload)
    elif ie_type == IEType.PRECEDENCE:
        return IE_Precedence(ie_length, ie_payload)
    elif ie_type == IEType.PDI:
        return IE_PDI(ie_length, ie_payload)
    elif ie_type == IEType.SOURCE_INTERFACE:
        return IE_SourceInterface(ie_length, ie_payload)
    elif ie_type == IEType.NETWORK_INSTANCE:
        return IE_NetworkInstance(ie_length, ie_payload)
    elif ie_type == IEType.F_TEID:
        return IE_FTEID(ie_length, ie_payload)
    elif ie_type == IEType.UE_IP_ADDRESS:
        return IE_UE_IP_Address(ie_length, ie_payload)
    elif ie_type == IEType.QFI:
        return IE_QFI(ie_length, ie_payload)
    elif ie_type == IEType.OUTER_HEADER_REMOVAL:
        return IE_OuterHeaderRemoval(ie_length, ie_payload)
    elif ie_type == IEType.APPLY_ACTION:
        return IE_ApplyAction(ie_length, ie_payload)
    elif ie_type == IEType.FORWARDING_PARAMETERS:
        return IE_ForwardingParameters(ie_length, ie_payload)
    elif ie_type == IEType.DESTINATION_INTERFACE:
        return IE_DestinationInterface(ie_length, ie_payload)
    else:
        return None
