# Snoopy - Packet Sniffing Tool

## Dependencies
- Python 3
- That's it lol. There's no need to install additional libraries.

## Supported Protocols
<table>
    <tr>
        <td><b>LINK LAYER</b></td>
        <td><b>NETWORK LAYER</b></td>
        <td><b>TRANSPORT LAYER</b></td>
        <td><b>APPLICATION LAYER</b></td>
    </tr>
    <tr>
        <td>ETHER</td>
        <td>IPV4</td>
        <td>UDP</td>
        <td>HTTP</td>
    </tr>
    <tr>
        <td></td>
        <td>IPV6</td>
        <td>TCP</td>
        <td>HTTPS (in progress)</td>
    </tr>
    <tr>
        <td></td>
        <td>ARP (in progress)</td>
        <td>ICMP</td>
        <td>PFCP</td>
    </tr>
    <tr>
        <td></td>
        <td></td>
        <td>SCTP (in progress)</td>
        <td></td>
    </tr>
</table>

## Usage
Please ensure to run `snoopy.py` as root / admin privileges.

Note that the `--network` and `--application` filters are mutually exclusive.
```commandline
usage: sudo python3 snoopy.py [-h] [--save] [--network  [...]] [--transport  [...] | --application  [...]]

A packet sniffer in the works.

optional arguments:
  -h, --help            show this help message and exit
  --save                Specify this argument to save sniffed packets into a pcapng file.
  --network  [ ...]     Supported Formats: ['IPV4', 'ARP', 'IPV6', 'UNKNOWN']
  --transport  [ ...]   Supported Formats: ['ICMP', 'TCP', 'UDP', 'SCTP', 'UNKNOWN']
  --application  [ ...] Supported Formats: ['HTTP', 'HTTPS', 'PFCP', 'UNKNOWN']
```

### Example 1: Sniff only IPV4 and UDP

```commandline
$ sudo python3 snoopy.py --network IPV4 --transport UDP
```
```
Ethernet Data:
        +Destination MAC: 00:00:00:00:00:00
        +Source MAC: 00:00:00:00:00:00
        +Network Type: IPV4
IPV4 Packet:
        +Version: 4
        +Header Length: 20
        +Time To Live: 64
        -Source IP: 127.0.0.4
        +Destination IP: 127.0.0.7
        +Transport Type: UDP
UDP Data:
        +Source Port: 8805
        +Destination Port: 8805
        +Length: 24
        +Checksum: 65076
        +Application Type: PFCP
PFCP Data:
        +Flags: 32
        +Message Type: HEARTBEAT_REQUEST
        +Length: 12
        +SEID: None
        +Sequence Number: 2928
        +Spare: 0
IE Type: RECOVERY_TIME_STAMP, IE Length: 4
        +Recovery Timestamp:
                +Epoch: 1679900266
                +Datetime: 27-03-2023 06:57:46 UTC
.
.
.
```

### Example 2: Sniff only IPV4 and HTTP
```commandline
$ sudo python3 snoopy.py --network IPV4 --application HTTP
```
```
Ethernet Data:
        +Destination MAC: 00:50:56:E0:88:CB
        +Source MAC: 00:0C:29:5B:31:A9
        +Network Type: IPV4
IPV4 Packet:
        +Version: 4
        +Header Length: 20
        +Time To Live: 64
        -Source IP: 172.16.109.133
        +Destination IP: 93.184.216.34
        +Transport Type: TCP
TCP Data:
        +Source Port: 51502
        +Destination Port: 80
        +Sequence: 3092133428
        +Acknowledgement: 2441842985
        +Offset: 20
        +FLAGS:
                +URG: 0
                +ACK: 1
                +PSH: 1
                +RST: 0
                +SYN: 0
                +FIN: 0
        +Application Type: HTTP
        +Request Method: GET
,       +Request URI: /
        +Request Version: HTTP/1.1
        +Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        +Accept-Language: en-US,en;q=0.5
        +Accept-Encoding: gzip, deflate
        +Connection: keep-alive
        +Upgrade-Insecure-Requests: 1
        +If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
        +If-None-Match: "3147526947+ident"
.
.
.
```

### Example 3: Sniff only unknown protocols 



