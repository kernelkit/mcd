#!/bin/sh
# Verifies that IPC clients get an error reply for a bad command, and
# that mcd keeps serving afterwards

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
echo $! >> "/tmp/$NM/PIDs"
sleep 2

# One row per line: description | command | expected text in the reply.
# The control rows (help, version) are in between, so a bad command that
# took the daemon down fails the row after it.
print "Sending commands ..."
fail=0
while IFS='|' read -r desc cmd expect; do
    reply=$(echo "$cmd" | socat -t 10 - UNIX-CONNECT:"/tmp/$NM/sock" 2>&1)
    if printf '%s\n' "$reply" | grep -qF "$expect"; then
	echo "ok:   $desc"
    else
	echo "FAIL: $desc: '$cmd' replied '$reply', expected '$expect'"
	fail=1
    fi
done <<EOF
control: help lists the commands|help|This help text
unknown command gets an error reply|bogus|No such command
unknown command still served after an error|version|mcd version
misspelled command gets an error reply|shw igmp|No such command
command word without its verb gets an error reply|status status|No such command
long garbage gets an error reply|$(printf 'x%.0s' $(seq 1 600))|No such command
control: mcd still answers after every error|show igmp|eth0
EOF

print "Analyzing ..."
kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
