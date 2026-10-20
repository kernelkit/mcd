#!/bin/sh
# Verifies the MRD router table, mctl show routers: mcd B hears mcd A's
# advertisements on the other end of a veth pair, IGMP and MLD, with
# A's advertisement interval, query interval and robustness.  A router
# is gone at once on its termination, and after NeighborDeadInterval,
# 3 * (4 + 2.5 %) = 13 s, when it goes silent without one.
#
#   mcd A -- a0 ==== b0 -- mcd B

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

cat <<EOF > "/tmp/$NM/a.conf"
mrd-interval 4
global-query-interval 30
robustness 3
iface a0 enable mrd on
EOF
cat <<EOF > "/tmp/$NM/b.conf"
iface b0 enable
EOF

# Start mcd A or B, its config, PID file, socket and log are named after it
start()
{
    ../src/mcd -i "$1" -f "/tmp/$NM/$1.conf" -p "/tmp/$NM/$1.pid" -l debug -n \
	       -u "/tmp/$NM/$1.sock" > "/tmp/$NM/$1.log" 2>&1 &
    echo $! >> "/tmp/$NM/PIDs"
}

# Routers mcd $1 lists, as "family router interval query-interval robustness"
routers()
{
    ../src/mctl -u "/tmp/$NM/$1.sock" show routers json \
	| jq -r '[.[] | "\(.family) \(.router) \(.interval) \(."query-interval") \(.robustness)"] | sort | join(",")'
}

# Wait up to $1 s for mcd B to list $2
await()
{
    for i in $(seq 1 "$1"); do
	[ "$(routers b)" = "$2" ] && return
	sleep 1
    done
}

fail=0
# What mcd $1 lists is $3
check()
{
    got=$(routers "$1")
    if [ "$got" = "$3" ]; then
	echo "ok:   $2"
    else
	echo "FAIL: $2: got '$got', expected '$3'"
	../src/mctl -u "/tmp/$NM/$1.sock" show routers
	fail=1
    fi
}

BOTH="ipv4 192.168.0.1 4 30 3,ipv6 fe80::1 4 30 3"

print "Starting mcd B, then A ..."
start b
tenacious 10 test -S "/tmp/$NM/b.sock"
start a
await 5 "$BOTH"
../src/mctl -u "/tmp/$NM/b.sock" show routers
check b "B hears A, IGMP and MLD" "$BOTH"
check a "A does not list itself" ""

print "Stopping A, it sends a termination ..."
kill "$(cat "/tmp/$NM/a.pid")"
await 3 ""
check b "A is gone at once" ""

print "Starting A again, then killing it without a termination ..."
start a
await 5 "$BOTH"
check b "B hears A again" "$BOTH"
kill -9 "$(cat "/tmp/$NM/a.pid")"
sleep 8
check b "A is still listed within NeighborDeadInterval" "$BOTH"
await 8 ""
check b "A timed out" ""

kill_pids
grep "MRD router" "/tmp/$NM/b.log"

[ "$fail" -eq 0 ] || FAIL

OK
