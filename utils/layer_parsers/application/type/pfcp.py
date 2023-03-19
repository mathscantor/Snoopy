from utils.layer_parsers.application.application import ApplicationLayer
import struct
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.dns import DNS


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


class CauseValues(Enum):
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


class SourceInterface(Enum):
    ACCESS = 0
    CORE = 1
    SGI_LAN_N6_LAN = 2
    CP_FUNCTION = 3
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class DestinationInterface(Enum):
    ACCESS = 0
    CORE = 1
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


class GateStatus(Enum):
    OPEN = 0
    CLOSED = 1
    CLOSED_RESERVED_2 = 2
    CLOSED_RESERVED_3 = 3
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TimerUnit(Enum):
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


class OuterHeaderRemovalDescription(Enum):
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


class FlowDirection(Enum):
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


class TimeUnit(Enum):
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


class BaseTimeInterval(Enum):
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

    def __init__(self, ie_length, ie_payload):
        self._ie_type = IEType.UNKNOWN
        self._ie_length = ie_length
        self._ie_payload = ie_payload

    def _parse_payload(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    @property
    def ie_type(self):
        return self._ie_type

    @property
    def ie_length(self):
        return self._ie_length

    @property
    def ie_payload(self):
        return self._ie_payload


class IE_NodeId(IE):

    def __init__(self, ie_length, ie_payload):
        IE.__init__(self, ie_length, ie_payload)
        self._ie_type = IEType.NODE_ID

        self._spare = None
        self._nodeid_type = None
        self._node_ip = None
        self._parse_data()

    def _parse_data(self):
        self._spare = self._ie_payload[0] >> 4
        self._nodeid_type = NodeIdType(self._ie_payload[0] & 0xf)

        print("CCC", self._ie_payload[1:self._ie_length])
        if self._nodeid_type == NodeIdType.IPV4:
            self._node_ip = IPv4Address(self._ie_payload[1:self._ie_length])
        elif self._nodeid_type == NodeIdType.IPV6:
            self._node_ip = IPv6Address(self._ie_payload[1:self._ie_length])
        elif self._nodeid_type == NodeIdType.FQDN:
            self._node_ip = DNS(self._ie_payload[1:self._ie_length])
        return

    def print_data(self):
        print("IE Type: {}, IE Length: {}\n"
              "\t+Spare: {}, Address Type: {}\n"
              "\t+Address: {}".format(self._ie_type.name, self._ie_length,
                                      self._spare, self._nodeid_type,
                                      self._node_ip))
        return

    @property
    def spare(self):
        return self._spare

    @property
    def nodeid_type(self):
        return self._nodeid_type

    @property
    def node_ip(self):
        return self._node_ip


class PFCP(ApplicationLayer):

    def __init__(self, application_type, application_data, src_port, dest_port):
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
        greedy_payload = None
        self._flags = self._application_data[0]
        self._flag_version = self._flags >> 5
        self._flag_spare1 = self._flags >> 4
        self._flag_spare2 = self._flags >> 3
        self._flag_follow_on = self._flags >> 2
        self._flag_message_priority = self._flags >> 1
        self._flag_seid = self._flags & 1

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

        print("@@@", len(greedy_payload))
        if len(greedy_payload) == 0:
            print("HERE")
            return
        else:
            print("HERE1")
            self._ie_list = []

        # Parse greedy payload here into their individual IEs
        # Loop until length reaches 0
        while len(greedy_payload) > 0:
            # First 4 bytes -- IE Type (2 bytes) and IE Length (2 bytes)
            ie_type_int, ie_length = struct.unpack('! H H', greedy_payload[0:4])
            ie_type = IEType(ie_type_int)
            print("BBB", ie_type.name)
            if ie_type == IEType.NODE_ID:
                ie_obj = IE_NodeId(ie_length=ie_length, ie_payload=greedy_payload[4: 4+ie_length])
                self._ie_list.append(ie_obj)

            greedy_payload = greedy_payload[4+ie_length:]
            print("AHHHH", len(greedy_payload))

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
              "\t+Sequence Number: {}\n"
              "\t+Spare: {}".format(self._flags,
                                    self._message_type.name,
                                    self._length,
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
