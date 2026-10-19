#!/bin/sh
# Verifies that bridge names are data, never shell: Linux allows ; $ ` |
# & > and ' in interface names, and mcd queries each bridge's router
# ports with a shell pipeline.  A name that ran as a command creates its
# pwn* file in mcd's working directory.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat
check_dep jq
check_dep bridge

# One row per line: description # bridge name # its router port.
# Every bridge gets a permanent router port, which must be listed.
ROWS=/tmp/$NM/rows
mkdir -p "/tmp/$NM"
cat <<'EOF' > "$ROWS"
control: plain name#br0#rp0
control: name jq cannot take as a .key#br-ok#rp1
command separator#b;>pwn1#rp2
command substitution#b$(>pwn2)#rp3
backtick substitution#b`>pwn3`#rp4
pipe#b|>pwn4#rp5
single quotes closing the quoting#b';>pwn5;'#rp6
background#b&>pwn6#rp7
EOF

print "Creating bridges ..."
addif eth0 192.168.0.1/24
while IFS='#' read -r desc br port; do
    ip link add "$br" type bridge
    ip link add "$port" type veth peer "$port"p
    ip link set "$port" master "$br"
    ip link set "$br" up
    ip link set "$port" up
    ip link set "$port"p up
    bridge link set dev "$port" mcast_router 2
done < "$ROWS"
ip -br l

print "Creating config ..."
cat <<EOF > "/tmp/$NM/config"
iface eth0 enable igmpv3
EOF
cat "/tmp/$NM/config"

print "Starting mcd ..."
mcd=$(pwd)/../src/mcd
(cd "/tmp/$NM" && exec "$mcd" -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock") &
echo $! >> "/tmp/$NM/PIDs"
sleep 2

for cmd in "show router-ports" "show router-ports json" "show igmp json"; do
    print "Querying IPC: $cmd ..."
    echo "$cmd" | socat -t 10 - UNIX-CONNECT:"/tmp/$NM/sock" > "/tmp/$NM/$(echo "$cmd" | tr ' ' -).out"
    cat "/tmp/$NM/$(echo "$cmd" | tr ' ' -).out"
done

kill_pids

print "Analyzing ..."
fail=0
while IFS='#' read -r desc br port; do
    pwn=$(echo "$br" | sed -n 's/.*\(pwn[0-9]\).*/\1/p')
    if [ -n "$pwn" ] && [ -e "/tmp/$NM/$pwn" ]; then
	echo "FAIL: $desc: bridge name '$br' ran as a shell command"
	fail=1
	continue
    fi
    if ! jq -e --arg br "$br" --arg port "$port" \
	 'any(.[]; .bridge == $br and .ports == [$port])' \
	 "/tmp/$NM/show-router-ports-json.out" >/dev/null; then
	echo "FAIL: $desc: show router-ports json lacks $br with router port $port"
	fail=1
	continue
    fi
    if ! jq -e --arg br "$br" --arg port "$port" \
	 '.["multicast-router-ports"] | any(.[]; .bridge == $br and .ports == [$port])' \
	 "/tmp/$NM/show-igmp-json.out" >/dev/null; then
	echo "FAIL: $desc: show igmp json lacks $br with router port $port"
	fail=1
	continue
    fi
    echo "ok:   $desc"
done < "$ROWS"

[ "$fail" -eq 0 ] || FAIL

OK
