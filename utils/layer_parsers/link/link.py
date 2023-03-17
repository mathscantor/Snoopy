class LinkLayer:

    def __init__(self, raw_data):
        self.raw_data = raw_data
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

    def print_raw_network_data(self):
        if self._network_data is not None and len(self._network_data) > 0:
            print("raw network data:")
            print(self._network_data)
        return

    @property
    def dest_mac(self):
        return self._dest_mac

    @property
    def src_mac(self):
        return self._src_mac

    @property
    def network_type(self):
        return self._network_type

    @property
    def network_data(self):
        return self._network_data
