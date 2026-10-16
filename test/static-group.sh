#!/bin/sh
# Verifies static-group: mcd joins the group in the kernel so the bridge
# learns a host membership for it.  The membership must survive SIGHUP,
# and a leave must be sent when mcd exits.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

GROUP=225.1.2.3

print "Check deps ..."
check_dep socat
check_dep jq
check_dep bridge
check_dep tshark

print "Creating bridge topology ..."
ip link add br0 type bridge mcast_snooping 1
ip link add veth0 type veth peer veth1
ip link set veth0 master br0
ip link set br0   up
ip link set veth0 up
ip link set veth1 up
ip addr add 192.168.0.1/24 dev br0

ip -br l

print "Creating config ..."
cat <<CONF > "/tmp/$NM/config"
iface br0 enable static-group $GROUP
CONF
cat "/tmp/$NM/config"

# Wait up to 10 sec for the host join to show up in the bridge MDB
wait_mdb()
{
    for _ in 1 2 3 4 5 6 7 8 9 10; do
	if bridge mdb show | grep -q "port br0 grp $GROUP"; then
	    return 0
	fi
	sleep 1
    done

    return 1
}

collect veth1

print "Starting mcd ..."
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -u "/tmp/$NM/sock" -l debug -n &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

print "Verifying host join in bridge MDB ..."
wait_mdb || FAIL "No host join for $GROUP in MDB"
bridge mdb show

print "Verifying mctl show groups ..."
../src/mctl -p -u "/tmp/$NM/sock" show groups
../src/mctl -p -u "/tmp/$NM/sock" show groups | grep -q "$GROUP" || FAIL "$GROUP missing from mctl"

print "Reloading mcd (SIGHUP) ..."
kill -HUP "$(cat "/tmp/$NM/pid")"
sleep 1
wait_mdb || FAIL "Host join for $GROUP lost on reload"

print "Stopping mcd ..."
kill "$(cat "/tmp/$NM/pid")"
sleep 2
kill_pids

print "Analyzing pcap ..."
tshark -n -r "/tmp/$NM/pcap" 2>/dev/null
tshark -n -r "/tmp/$NM/pcap" 2>/dev/null | grep -q "Join group $GROUP"  || FAIL "No join report for $GROUP"
tshark -n -r "/tmp/$NM/pcap" 2>/dev/null | grep -q "Leave group $GROUP" || FAIL "No leave report for $GROUP"

OK
