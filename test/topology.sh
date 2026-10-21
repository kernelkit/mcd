#!/bin/sh
# Verifies the topology query: a general query when a bridge port
# starts forwarding, on the bridge itself and on a VLAN interface on
# top of it.  Also that a flapping port is rate limited, and that
# 'no topology-query' turns it off.
#
# Query interval 12 gives a startup burst of 2 queries 3 s apart.
# Counting 10 s after start, with a port flap at 5 s:
#
#   t=0 query, t=3 burst, t=5 flap query, t=8 burst again  =>  4
#   t=0 query, t=3 burst, no flap query                    =>  2

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep tshark

print "Creating world ..."
ip link add br0 type bridge
ip link add p1 type veth peer p1p
ip link add p2 type veth peer p2p
for p in p1 p2; do
    ip link set $p master br0
    ip link set $p up
    ip link set ${p}p up
done
ip link set br0 up
ip addr add 192.168.0.1/24 dev br0
ip link add link br0 name vlan10 type vlan id 10
ip link set vlan10 up
ip addr add 192.168.10.1/24 dev vlan10
ip -br l

# Count the IGMP general queries sent on an interface
queries()
{
    tshark -n -r "/tmp/$NM/$1.pcap" -Y "igmp.type == 0x11 && !vlan" 2>/dev/null | wc -l
}

# Run mcd for 10 s with the given config, flap p2 $2 times at 5 s
run()
{
    cat <<EOF > "/tmp/$NM/config"
global-query-interval 12
$1
iface br0 enable mld off
iface vlan10 enable mld off
EOF
    capture br0 "/tmp/$NM/br0.pcap"
    capture vlan10 "/tmp/$NM/vlan10.pcap"

    ../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" \
	       > "/tmp/$NM/log" 2>&1 &
    echo $! >> "/tmp/$NM/PIDs"
    sleep 5

    i=0
    while [ $i -lt "$2" ]; do
	ip link set p2 down
	ip link set p2 up
	i=$((i + 1))
    done
    sleep 5

    kill_pids
    grep -i "forwarding\|query" "/tmp/$NM/log" | head -20
}

fail=0
# Queries on br0 and vlan10 both within $2..$3
check()
{
    br0=$(queries br0)
    vlan10=$(queries vlan10)
    echo " => $br0 queries on br0, $vlan10 on vlan10, expected $2..$3"
    if [ "$br0" -ge "$2" ] && [ "$br0" -le "$3" ] &&
       [ "$vlan10" -ge "$2" ] && [ "$vlan10" -le "$3" ]; then
	echo "ok:   $1"
    else
	echo "FAIL: $1"
	fail=1
    fi
}

print "Port flap, expect a query on br0 and vlan10 ..."
run "" 1
check "one flap" 4 4

print "Port flapping ten times, expect few queries ..."
run "" 10
check "ten flaps" 3 6

print "Port flap with no topology-query ..."
run "no topology-query" 1
check "disabled" 2 2

[ "$fail" -eq 0 ] || FAIL

OK
