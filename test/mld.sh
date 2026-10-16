#!/bin/sh
# Verifies MLD querier operation alongside IGMP: one MLDv2 General
# Query from the link-local address, one IGMPv3 General Query from the
# IPv4 address, and a listener report for a static IPv6 group on eth0.
# eth1 runs IGMP only, eth2 MLDv1 only.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

GROUP=ff05::1234

print "Check deps ..."
check_dep tshark

print "Creating world ..."
for iface in eth0 eth1 eth2; do
    ip link add $iface type dummy
    ip link set $iface up
    ip link set $iface multicast on
done
ip addr add 192.168.0.1/24 dev eth0
ip addr add fe80::1/64 dev eth0
ip addr add 2001:db8::1/64 dev eth0

ip -br a

print "Creating config ..."
cat <<CONF > "/tmp/$NM/config"
iface eth0 enable static-group $GROUP
iface eth1 enable mld off
iface eth2 enable igmp off mldv1
CONF
cat "/tmp/$NM/config"

collect eth0

print "Starting mcd ..."
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -u "/tmp/$NM/sock" -l debug -n > "/tmp/$NM/log" 2>&1 &
echo $! >> "/tmp/$NM/PIDs"
sleep 2

print "Querying interface status ..."
../src/mctl -p -u "/tmp/$NM/sock" show interfaces
../src/mctl -p -u "/tmp/$NM/sock" show interfaces > "/tmp/$NM/ifaces"
grep -q "^eth0 .*MLD .*fe80::1 " "/tmp/$NM/ifaces" || FAIL "No MLD querier on fe80::1"
grep -q "^eth1 .*IGMP "       "/tmp/$NM/ifaces" || FAIL "No IGMP querier on eth1"
grep -q "^eth1 .*MLD "        "/tmp/$NM/ifaces" && FAIL "MLD querier on eth1 despite mld off"
grep -q "^eth2 .*IGMP "       "/tmp/$NM/ifaces" && FAIL "IGMP querier on eth2 despite igmp off"
grep -q "^eth2 .*MLD .* 1$"   "/tmp/$NM/ifaces" || FAIL "No MLDv1 querier on eth2"

kill_pids

print "Daemon log ..."
cat "/tmp/$NM/log"
grep -q "SENT MLDv1 listener query .* on eth2" "/tmp/$NM/log" || FAIL "No MLDv1 query sent on eth2"

print "Analyzing pcap ..."
tshark -n -r "/tmp/$NM/pcap" 2>/dev/null
mld=$(tshark -n -r "/tmp/$NM/pcap" -Y 'icmpv6.type == 130 && ipv6.src == fe80::1' 2>/dev/null | wc -l)
igmp=$(tshark -n -r "/tmp/$NM/pcap" -Y 'igmp.type == 0x11' 2>/dev/null | wc -l)
rep=$(tshark -n -r "/tmp/$NM/pcap" -Y "icmpv6.type == 143 && icmpv6.mldr.mar.multicast_address == $GROUP" 2>/dev/null | wc -l)

echo " => $mld MLD Query from fe80::1, expected 1"
echo " => $igmp IGMP Query, expected 1"
echo " => $rep MLDv2 Report for $GROUP, expected >= 1"
# shellcheck disable=SC2086
[ $mld -eq 1 ] || FAIL
[ $igmp -eq 1 ] || FAIL
[ $rep -ge 1 ] || FAIL

OK
