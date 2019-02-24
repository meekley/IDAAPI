## IDAAPI - REST API Client for Check Point Identity Awareness GW

## Installation

```
git clone https://github.com/meekley/IDAAPI.git

```

## Instantiate a client and add identity:

```python
from Iden import Iden

gw_ip = "172.25.1.100" # ip of the Check  Point firewall gateway
secret = "123456abcd" # Identity Awareness API secret

client = Iden.IDA(gw_ip, secret)

host_ip = "192.168.1.20" # ip address of the host to be added to the access role
host_tag = "test_tag" # tag for the host added - can be more than one (list)
role = "test_role" # access role object that the IP of the host will be added to
timeout = 300 # identity timeout - 300 seconds is minimum

result = client.ida_add(host_ip, host_tag, role, timeout)
```

## Requirements

#### Python 2.7

