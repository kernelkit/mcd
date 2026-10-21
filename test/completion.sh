#!/bin/sh
# Verifies shell completion for mctl: mctl -C WORD... prints the
# candidates for the last, partial, word from the running mcd's
# command list, and the bash completion function builds on it

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep socat
check_dep bash

print "Creating world ..."
addif eth0 192.168.0.1/24

print "Creating config ..."
cat <<EOF > "/tmp/$NM/config"
iface eth0 enable igmpv3
EOF
cat "/tmp/$NM/config"

print "Starting mcd ..."
SOCK=/tmp/$NM/sock
../src/mcd -f "/tmp/$NM/config" -p "/tmp/$NM/pid" -l debug -n -u "$SOCK" &
echo $! >> "/tmp/$NM/PIDs"
tenacious 10 test -S "$SOCK"

PATH=$(pwd)/../src:$PATH
export PATH

# Candidates as one sorted line
line()
{
    # shellcheck disable=SC2046
    echo $(cut -f1 | LC_ALL=C sort)
}

# The bash function, driven without a terminal
bashcomp()
{
    bash -c '
	. ../completions/bash/mctl
	COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1))
	_mctl
	printf "%s\n" "${COMPREPLY[@]}"' bash "$@"
}

fail=0
check()
{
    if [ "$2" = "$3" ]; then
	echo "ok:   $1"
    else
	echo "FAIL: $1: got '$3', expected '$2'"
	fail=1
    fi
}

# One row per line: description | words so far, the last one partial,
# '' for an empty one | expected candidates, sorted
print "Checking mctl -C ..."
while IFS='|' read -r desc words expect; do
    eval "set -- $words"
    check "$desc" "$expect" "$(mctl -u "$SOCK" -C "$@" 2>&1 | line)"
done <<EOF
first word|''|check help show version
no word at all||check help show version
partial first word|sh|show
after show, json is the hidden show's option|show ''|compat groups igmp interfaces json mdb router-ports routers status
partial second word|show i|igmp interfaces
option of a command|show igmp ''|json
partial option|show router-ports j|json
nothing after the option|show igmp json ''|
unknown command|bogus ''|
EOF

# A candidate that completes a command has its description after a
# tab, an intermediate word has none
print "Checking descriptions ..."
check "description" "version	Show daemon version" "$(mctl -u "$SOCK" -C vers)"
check "no description on an intermediate word" "show" "$(mctl -u "$SOCK" -C sh)"

print "Checking with no daemon ..."
got=$(mctl -u "/tmp/$NM/nosuch" -C '' 2>&1)
check "no daemon, no candidates, exit $?" "" "$got"

print "Checking bash completion ..."
while IFS='|' read -r desc words expect; do
    eval "set -- $words"
    check "$desc" "$expect" "$(bashcomp mctl -u "$SOCK" "$@" | line)"
done <<EOF
first word|''|check help show version
partial first word|sh|show
after show|show ''|compat groups igmp interfaces json mdb router-ports routers status
option of a command|show igmp ''|json
options|-|--help --ident --ipc --monitor --no-heading --plain --version -h -i -m -p -t -u -v
long options|--|--help --ident --ipc --monitor --no-heading --plain --version
EOF

kill_pids

[ "$fail" -eq 0 ] || FAIL

OK
