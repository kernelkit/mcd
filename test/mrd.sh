#!/bin/sh
# Verifies Multicast Router Discovery, RFC 4286, on an interface with
# 'mrd on': three initial advertisements for IGMP and MLD within six
# seconds, an advertisement in answer to a solicitation, and a
# termination on exit.  Nothing without 'mrd on'.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep tshark

print "Creating world ..."
addif eth0 192.168.0.1/24
ip addr add fe80::1/64 dev eth0

# MRD message types in the capture, one tshark pass per run
types()
{
    tshark -n -r "/tmp/$NM/pcap" -T fields -e igmp.type -e icmpv6.type 2>/dev/null \
	| tr -d '\t' | sort | uniq -c | tee "/tmp/$NM/types"
}

# Number of messages of a type, in tshark's spelling: 0x30 or 151
count()
{
    awk -v t="$1" '$2 == t { print $1 }' "/tmp/$NM/types" | grep . || echo 0
}

fail=0
# Messages of $4 between $2 and $3
check()
{
    n=$(count "$4")
    echo " => $n $1, expected $2..$3"
    if [ "$n" -ge "$2" ] && [ "$n" -le "$3" ]; then
	echo "ok:   $1"
    else
	echo "FAIL: $1"
	fail=1
    fi
}

run()
{
    cat <<EOF > "/tmp/$NM/config"
iface eth0 enable $1
EOF
    collect eth0
    ../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" \
	       > "/tmp/$NM/log" 2>&1 &
    MCD=$!
    sleep "$2"
}

# mcd first, its terminations must reach the capture before it stops
stop()
{
    kill "$MCD"
    wait "$MCD" 2>/dev/null
    sleep 1
    kill_pids
}

print "Starting mcd with mrd on ..."
run "mrd on" 7
../src/mctl -p -u "/tmp/$NM/sock" show interfaces

print "Soliciting ..."
./solicit eth0
sleep 3

print "Stopping mcd ..."
stop
grep -i "mrd" "/tmp/$NM/log"
types

check "IGMP advertisements, 3 initial and 1 solicited" 4 4 0x30
check "MLD advertisements, 3 initial and 1 solicited"  4 4 151
check "IGMP terminations" 1 1 0x32
check "MLD terminations"  1 1 153

print "Starting mcd without mrd ..."
run "" 3
stop
types
check "IGMP advertisements without mrd on" 0 0 0x30
check "MLD advertisements without mrd on"  0 0 151

[ "$fail" -eq 0 ] || FAIL

OK
