#!/bin/sh
# Verifies that mctl survives any command list from the daemon: mctl
# builds its commands from the 'help' reply, one word per argument, and
# stores up to MAXARGS (32) of them.  A fake daemon (socat) answers
# with a command of N words, then a 'version' command mctl must list.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat

SOCK=/tmp/$NM/sock
REPLY=/tmp/$NM/reply
mkdir -p "/tmp/$NM"
: > "$REPLY"

print "Starting fake mcd ..."
socat UNIX-LISTEN:"$SOCK",fork SYSTEM:"cat $REPLY" &
echo $! >> "/tmp/$NM/PIDs"
tenacious 10 test -S "$SOCK"

# One row per line: description # words in the command # mctl exit code
print "Checking mctl -h ..."
fail=0
while IFS='#' read -r desc words expect; do
    { seq -s ' ' -f 'w%g' 1 "$words" | tr -d '\n'
      printf '\tLong command\n'
      printf 'version\tShow daemon version\n'
    } > "$REPLY"

    ../src/mctl -u "$SOCK" -h > "/tmp/$NM/out" 2>&1
    rc=$?

    if [ "$rc" -ne "$expect" ]; then
	echo "FAIL: $desc: mctl -h exited $rc, expected $expect"
	tail -5 "/tmp/$NM/out"
	fail=1
    elif ! grep -q '^  version  *Show daemon version' "/tmp/$NM/out"; then
	echo "FAIL: $desc: the command after it is not listed"
	cat "/tmp/$NM/out"
	fail=1
    else
	echo "ok:   $desc"
    fi
done <<EOF
control: one word#1#0
two words, like show igmp#2#0
exactly MAXARGS words#32#0
one word past MAXARGS#33#0
far past MAXARGS#300#0
EOF

kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
