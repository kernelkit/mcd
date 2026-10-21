#!/bin/sh
# Verifies the group membership interval per interface: a group with
# a silent member times out after 2 * 4 + 2 = 10 s with only a per
# interface query-interval 4, not after the global 2 * 125 + 2 s.
# The member joins on b0, mcd runs on a0, then tc drops the member's
# reports to the queries.
#
#   mcd -- a0 ==== b0 -- member of 225.1.1.1

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

GROUP=225.1.1.1

print "Check deps ..."
check_dep socat
check_dep tc

print "Creating world ..."
ip link add a0 type veth peer b0
for i in a0 b0; do
    ip link set $i up
    ip link set $i multicast on
done
ip addr add 192.168.0.1/24 dev a0
ip addr add 192.168.0.2/24 dev b0
ip -br a

tc qdisc add dev b0 clsact || SKIP "tc clsact not available"

cat <<EOF > "/tmp/$NM/config"
global-response-interval 2
iface a0 enable query-interval 4 mld off
EOF
cat "/tmp/$NM/config"

print "Starting mcd ..."
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" \
	   > "/tmp/$NM/log" 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
tenacious 10 test -S "/tmp/$NM/sock"

print "Joining $GROUP on b0 ..."
socat -u UDP4-RECV:5000,ip-add-membership=$GROUP:b0 /dev/null &
echo $! >> "/tmp/$NM/PIDs"
tenacious 5 grep -q "$GROUP" "/tmp/$NM/log"
grep "$GROUP" "/tmp/$NM/log"

print "Member goes silent ..."
tc filter add dev b0 egress prio 1 protocol ip u32 match ip protocol 2 0xff action drop
tenacious 15 grep -q "Group membership timeout for $GROUP on a0" "/tmp/$NM/log"
grep "membership timeout" "/tmp/$NM/log"
kill_pids

OK
