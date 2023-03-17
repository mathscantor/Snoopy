from utils.layer_parsers.link.mappings import NetworkType


class NetworkLayer():

    def __init__(self, network_type, network_data):
        self._network_type = network_type
        if self._network_type == NetworkType.UNKNOWN:
            print("Error in network type! Unable to do parsing in utils/layer_parsers/network.py!")
            print("Exiting...")
            exit(1)

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

    def print_raw_transport_data(self):
        if self._transport_data is not None and len(self._transport_data) > 0:
            print("raw transport data:")
            print(self._transport_data)
        return

    @property
    def version(self):
        return self._version

    @property
    def transport_type(self):
        return self._transport_type

    @property
    def transport_data(self):
        return self._transport_data

    @property
    def src_ip(self):
        return self._src_ip

    @property
    def dest_ip(self):
        return self._dest_ip


