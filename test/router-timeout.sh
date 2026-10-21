#!/bin/sh
# Verifies the router timeout (other querier present interval): unless
# set, it follows the configured robustness, query and response interval
# per RFC 3376, robustness * query-interval + response-interval / 2

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat

print "Creating world ..."
addif eth0 192.168.0.1/24

# One row per line: description | global settings (';' between lines) |
# expected router timeout.
print "Checking router timeout ..."
fail=0
while IFS='|' read -r desc globals expect; do
    printf '%s\n' "$globals" | tr ';' '\n' > "/tmp/$NM/config"
    echo "iface eth0 enable igmpv3" >> "/tmp/$NM/config"

    ../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" \
	2>"/tmp/$NM/mcd.log" &
    pid=$!
    tenacious 10 test -S "/tmp/$NM/sock"
    got=$(echo "show igmp" | socat -t 10 - UNIX-CONNECT:"/tmp/$NM/sock" \
	      | sed -n 's/^Router Timeout (default): *\([0-9]*\).*/\1/p')
    kill $pid
    wait $pid 2>/dev/null
    rm -f "/tmp/$NM/sock"

    if [ "$got" = "$expect" ]; then
	echo "ok:   $desc ($got)"
    else
	echo "FAIL: $desc: router timeout '$got', expected '$expect'"
	cat "/tmp/$NM/mcd.log"
	fail=1
    fi
done <<EOF
defaults: 2 * 125 + 10 / 2|# defaults|255
query interval: 2 * 10 + 10 / 2|global-query-interval 10|25
robustness: 3 * 10 + 10 / 2|robustness 3;global-query-interval 10|35
response interval: 2 * 10 + 4 / 2|global-query-interval 10;global-response-interval 4|22
lower bound: 2 * 1 + 1 / 2|global-query-interval 1;global-response-interval 1|2
explicit router-timeout wins|global-query-interval 10;router-timeout 15|15
explicit router-timeout wins whatever the order|router-timeout 15;global-query-interval 10|15
EOF

[ "$fail" -eq 0 ] || FAIL

OK
