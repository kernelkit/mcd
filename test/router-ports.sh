#!/bin/sh
# Verifies per-bridge multicast router port listing.
#
# Tests the 'show router-ports [json]' command and verifies that
# 'show igmp json' outputs multicast-router-ports as a per-bridge
# array of objects rather than a flat list of port names.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat
check_dep jq
check_dep bridge

print "Creating bridge topology ..."
ip link add br0 type bridge vlan_filtering 1
ip link add veth0 type veth peer veth1
ip link add veth2 type veth peer veth3
ip link set veth0 master br0
ip link set veth2 master br0
ip link set br0    up
ip link set veth0  up
ip link set veth1  up
ip link set veth2  up
ip link set veth3  up
ip addr add 192.168.0.1/24 dev br0

ip -br l

print "Creating config ..."
cat <<EOF > "/tmp/$NM/config"
iface br0 enable igmpv3
EOF
cat "/tmp/$NM/config"

print "Starting mcd ..."
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" &
echo $! >> "/tmp/$NM/PIDs"
sleep 2

print "Querying IPC: help ..."
echo "help" | socat - UNIX-CONNECT:"/tmp/$NM/sock" | tee "/tmp/$NM/help.txt"

print "Querying IPC: show router-ports ..."
echo "show router-ports" | socat - UNIX-CONNECT:"/tmp/$NM/sock" | tee "/tmp/$NM/rp.txt"

print "Querying IPC: show router-ports json ..."
echo "show router-ports json" | socat - UNIX-CONNECT:"/tmp/$NM/sock" | tee "/tmp/$NM/rp.json"
echo

print "Querying IPC: show igmp json ..."
echo "show igmp json" | socat - UNIX-CONNECT:"/tmp/$NM/sock" | tee "/tmp/$NM/igmp.json"
echo

kill_pids

print "Analyzing ..."

# New command must be listed in help
grep -q "show router-ports" "/tmp/$NM/help.txt" || FAIL "show router-ports missing from help"

# Text mode must show bridge name
grep -q "br0" "/tmp/$NM/rp.txt" || FAIL "br0 missing from show router-ports text output"

# JSON output must be a valid array
jq -e 'type == "array"' "/tmp/$NM/rp.json" \
    || FAIL "show router-ports json: not a JSON array"

# Each element must have 'bridge' and 'ports' keys
jq -e 'all(.[]; has("bridge") and has("ports") and (.ports | type == "array"))' \
    "/tmp/$NM/rp.json" \
    || FAIL "show router-ports json: elements missing bridge/ports keys"

# br0 must be listed in router-ports json
jq -e 'any(.[]; .bridge == "br0")' "/tmp/$NM/rp.json" \
    || FAIL "show router-ports json: br0 not listed"

# show igmp json: multicast-router-ports must be an array
jq -e '.["multicast-router-ports"] | type == "array"' "/tmp/$NM/igmp.json" \
    || FAIL "show igmp json: multicast-router-ports is not an array"

# show igmp json: elements must have per-bridge structure (not flat port strings)
jq -e '.["multicast-router-ports"] | all(.[]; has("bridge") and has("ports") and (.ports | type == "array"))' \
    "/tmp/$NM/igmp.json" \
    || FAIL "show igmp json: multicast-router-ports not in per-bridge format"

# br0 must appear in multicast-router-ports
jq -e '.["multicast-router-ports"] | any(.[]; .bridge == "br0")' "/tmp/$NM/igmp.json" \
    || FAIL "show igmp json: br0 missing from multicast-router-ports"

OK
