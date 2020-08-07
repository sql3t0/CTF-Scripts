#!/bin/bash
# Pass IP address as paramter to run in a espcific target
[ -z $1 ] && IP='127.0.0.1' || IP=$1
ports="21 22 23 25 53 80 110 111 115 135 139 143 194 443 445 993 995 1337 1433 1723 3306 3389 5632 5900 5901 6112 7070 8080 9090"
for port in $ports ;do
    	timeout 1 bash -c "(</dev/tcp/$IP/$port) 2>/dev/null && if [ $port = \"443\" ]; then echo -e '[\e[102m ON \e[0m] https://$IP:$port ' ;else echo -e '[\e[102m ON \e[0m] http://$IP:$port ' ;fi";
done
