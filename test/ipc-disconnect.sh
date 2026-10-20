#!/bin/sh
# Verifies that mcd survives an IPC client that disconnects before
# reading its reply, i.e., a reply write() to a closed peer (SIGPIPE)

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat

print "Creating world ..."
addif eth0 192.168.0.1/24

print "Creating config ..."
cat <<EOF > "/tmp/$NM/config"
iface eth0 enable igmpv3
EOF
cat "/tmp/$NM/config"

print "Starting mcd ..."
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "/tmp/$NM/sock" &
PID=$!
echo $PID >> "/tmp/$NM/PIDs"
sleep 2

# One row per line: description | command | expected reply afterwards.
# mcd is stopped while the client connects, sends and gives up (socat
# waits 0.1 s), so by the time mcd runs again the peer is gone and the
# reply goes nowhere.  mcd must then still be alive and answer 'version'.
print "Disconnecting clients ..."
fail=0
while IFS='|' read -r desc cmd expect; do
    kill -STOP $PID
    echo "$cmd" | socat -t 0.1 - UNIX-CONNECT:"/tmp/$NM/sock" >/dev/null 2>&1
    kill -CONT $PID
    sleep 1

    if ! kill -0 $PID 2>/dev/null; then
	echo "FAIL: $desc: mcd died replying to '$cmd'"
	fail=1
	break
    fi
    reply=$(echo "version" | socat -t 2 - UNIX-CONNECT:"/tmp/$NM/sock" 2>&1)
    if printf '%s\n' "$reply" | grep -qF "$expect"; then
	echo "ok:   $desc"
    else
	echo "FAIL: $desc: after '$cmd', 'version' replied '$reply'"
	fail=1
    fi
done <<EOF
help reply to a closed peer|help|mcd version
version reply to a closed peer|version|mcd version
show reply to a closed peer|show igmp|mcd version
json show reply to a closed peer|show igmp json|mcd version
error reply to a closed peer|bogus|mcd version
EOF

print "Analyzing ..."
kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
