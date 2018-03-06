# Shodan_So
Search Assistant: Searching shodan via API.

```
usage: Shodan_So.py [-search Apache] [-f ips.txt] [-ip 217.140.75.46]
                    [-iprg 217.140.75.46/24] [--hostnameonly] [--history]
                    [--page 1] [--list_ip] [--list_ip_port]

Shodan_So - Search Assistant: Searching shodan via API. --By: Zev3n


optional arguments:
  -search Apache        when searching Shodan for a string.
  -f ips.txt            Using THe Ips List - File containing IPs to search
                        shodan for.
  -ip 217.140.75.46     Shodan Host Search against IP & return results from
                        Shodan about a specific IP.
  -iprg 217.140.75.46/24
                        Used to return results from Shodan about a specific
                        CIDR to IP range .
  --hostnameonly        Only provide results with a Shodan stored hostname.
  --history             Return all historical banners.
  --page 1              Page number of results to return (default 1 (first
                        page)).
  --list_ip             Singled out IP address from query results.
  --list_ip_port        Singled out IP address with port from query results.
```

THanks to the legend Hood3dRob1n & Lucifer HR

第一次写工具，喜欢的朋友给个star吧~
