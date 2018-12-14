# Shodan_So
Search Assistant: Searching shodan via API.

```
usage: Shodan_So.py [-search Apache] [-f ips.txt] [-ip 217.140.75.46]
                    [-iprg 217.140.75.46/24] [--hostnameonly] [--history]
                    [--page 1] [--list_ip] [--list_ip_port]

Shodan_So - Search Assistant: Searching shodan via API. --By: Zev3n


optional arguments:
  -f ips.txt            Using THe Ips List - File containing IPs to search
                        shodan for.
  --ip 217.140.75.46/24-217.140.75.46/26
                        Shodan Host Search against IP/IP range & return
                        results from Shodan about a it/them.
  --search Apache       when searching Shodan for a string.
  --hostnameonly        Only provide results with a Shodan stored hostname.
  --history             Return all historical banners.
  --page 1              Page number of results to return (default 1 (first
                        page)).
  --list_ip             Singled out IP address from query results.
  --list_ip_port        Singled out IP address with port from query results.
```

Thanks to the legend Hood3dRob1n & Lucifer HR

第一次写工具，喜欢的朋友给个star吧~

## 1.2版本更新说明：
- 自己用着实在不顺手，修复了几个参数的逻辑bug。
- 优化了输出的格式，包括颜色和分层，较直观。
- 增加了按范围查询ip的功能。

