#!/bin/sh
# Verifies the router timeout, the other querier present interval, per
# interface: with only a per interface query-interval 4, mcd B backs
# off for 2 * 4 + 10 / 2 = 13 s, not the global 255 s, and takes over
# from mcd A within that once A goes silent.  IGMP and MLD each.
#
#   mcd A -- a0 ==== b0 -- mcd B
#   lower address wins the election

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep jq

print "Creating world ..."
ip link add a0 type veth peer b0
for i in a0 b0; do
    ip link set $i up
    ip link set $i multicast on
done
ip addr add 192.168.0.1/24 dev a0
ip addr add fe80::1/64 dev a0
ip addr add 192.168.0.2/24 dev b0
ip addr add fe80::2/64 dev b0
ip -br a

for x in a b; do
    echo "iface ${x}0 enable query-interval 4" > "/tmp/$NM/$x.conf"
done

start()
{
    ../src/mcd -i "$1" -f "/tmp/$NM/$1.conf" -p "/tmp/$NM/$1.pid" -l debug -n \
	       -u "/tmp/$NM/$1.sock" > "/tmp/$NM/$1.log" 2>&1 &
    echo $! >> "/tmp/$NM/PIDs"
}

# The querier mcd B sees and its timeout, per family: "ipv4 ADDR TMO,..."
querier()
{
    ../src/mctl -u "/tmp/$NM/b.sock" show interfaces json \
	| jq -r '[.[] | "\(.family) \(.querier) \(.timeout // "-")"] | sort | join(",")'
}

fail=0
check()
{
    if [ "$2" ]; then
	echo "ok:   $1"
    else
	echo "FAIL: $1: $(querier)"
	../src/mctl -u "/tmp/$NM/b.sock" show interfaces
	fail=1
    fi
}

print "Starting mcd A, then B ..."
start a
tenacious 10 test -S "/tmp/$NM/a.sock"
start b
tenacious 10 test -S "/tmp/$NM/b.sock"
for i in $(seq 1 6); do
    q=$(querier)
    echo "$q" | grep -q 'ipv4 192.168.0.1 .*ipv6 fe80::1 ' && break
    sleep 1
done
../src/mctl -u "/tmp/$NM/b.sock" show interfaces
echo " => $q"

# Timeouts count down from 13, A queries every 4 s
check "B backs off to A, IGMP and MLD" \
      "$(echo "$q" | grep 'ipv4 192.168.0.1 ' | grep 'ipv6 fe80::1 ')"
for t in $(echo "$q" | tr ',' '\n' | awk '{ print $3 }'); do
    [ "$t" -le 13 ] && [ "$t" -gt 0 ] || { echo "FAIL: timeout $t, expected 1..13"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "ok:   timeouts from the interface's query interval"
rt=$(../src/mctl -u "/tmp/$NM/b.sock" show interfaces json | jq -r '[.[]."router-timeout"] | join(",")')
check "router-timeout in show interfaces is the interface's, $rt" "$([ "$rt" = "13,13" ] && echo y)"

print "Stopping A, B takes over within 13 s ..."
kill -9 "$(cat "/tmp/$NM/a.pid")"
for i in $(seq 1 16); do
    q=$(querier)
    [ "$q" = "ipv4 192.168.0.2 -,ipv6 fe80::2 -" ] && break
    sleep 1
done
echo " => $q after $i s"
check "B takes over, IGMP and MLD" "$(echo "$q" | grep -x 'ipv4 192.168.0.2 -,ipv6 fe80::2 -')"

kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
