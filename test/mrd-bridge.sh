#!/bin/sh
# Verifies that a snooping bridge learns its router port from mcd's
# MRD advertisements alone, IGMP and MLD each.  mcd runs on br0, a
# veth pair connects it to br1, which snoops.  The Linux bridge also
# learns router ports from queries, so those are dropped on the way
# in to br1 with tc.
#
#   br0 -- a0 ==== b0 -- br1
#   mcd            tc drop

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

MRD4=224.0.0.106
MRD6=ff02::6a

print "Check deps ..."
check_dep jq
check_dep bridge
check_dep tc

print "Creating world ..."
ip link add br0 type bridge
ip link add br1 type bridge
ip link add a0 type veth peer b0
ip link set a0 master br0
ip link set b0 master br1
for i in br0 br1 a0 b0; do
    ip link set $i up
done
ip addr add 192.168.0.1/24 dev br0
ip addr add fe80::1/64 dev br0
ip -br l

tc qdisc add dev b0 clsact || SKIP "tc clsact not available"

# Drop frames to a group on their way in to br1, prio is the handle
drop()
{
    case $2 in
	*:*) tc filter add dev b0 ingress prio "$1" protocol ipv6 u32 match ip6 dst "$2"/128 action drop;;
	*)   tc filter add dev b0 ingress prio "$1" protocol ip   u32 match ip  dst "$2"/32  action drop;;
    esac
}

allow()
{
    tc filter del dev b0 ingress prio "$1"
}

# b0 is listed as a router port on br1
learned()
{
    bridge -j -d mdb show | jq -e 'any(.[].router.br1[]?; .port == "b0")' >/dev/null
}

cat <<EOF > "/tmp/$NM/config"
iface br0 enable mrd on
EOF

# Start mcd, the initial advertisements follow within six seconds
run()
{
    ../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" \
	       > "/tmp/$NM/log" 2>&1 &
    echo $! >> "/tmp/$NM/PIDs"
}

# Wait for the router port, up to 10 s
settle()
{
    for i in 1 2 3 4 5 6 7 8 9 10; do
	learned && return
	sleep 1
    done
}

fail=0
check()
{
    learned && got=yes || got=no
    if [ "$got" = "$2" ]; then
	echo "ok:   $1"
    else
	echo "FAIL: $1"
	bridge -d mdb show
	grep -i "mrd" "/tmp/$NM/log"
	fail=1
    fi
}

print "Dropping queries and advertisements ..."
drop 1 224.0.0.1
drop 2 ff02::1
drop 3 $MRD4
drop 4 $MRD6
run
sleep 7
check "nothing reaches br1, no router port" no
kill_pids

print "Letting MLD advertisements through ..."
allow 4
run
settle
check "router port from the MLD advertisement" yes
kill_pids

print "Clearing the router port ..."
bridge link set dev b0 mcast_router 0
bridge link set dev b0 mcast_router 1
check "router port cleared" no

print "Letting IGMP advertisements through instead ..."
drop 4 $MRD6
allow 3
run
settle
check "router port from the IGMP advertisement" yes
kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
