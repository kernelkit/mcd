# Verifies that mcd fails, loudly, when it cannot fork to daemonize: the
# fork_fail shim makes fork() fail, and mcd must not exit 0 as if the
# daemon were running.
#
# Usage: test_daemonize MCD SHIM
#
# Built with writeShellApplication (errexit, nounset, pipefail): the
# exit code under test is caught with || rc=$?.

mcd=$1
shim=$2
out=$(mktemp)

# One row per line: description # mcd arguments # FORK_ERRNO #
# expected exit code # expected text on stderr (empty: any)
fail=0
while IFS='#' read -r desc args errno expect text; do
    rc=0
    # shellcheck disable=SC2086
    FORK_ERRNO=$errno LD_PRELOAD=$shim "$mcd" $args -f /dev/null 2>"$out" || rc=$?

    if [ "$rc" -ne "$expect" ]; then
	echo "FAIL: $desc: exit $rc, expected $expect"
	cat "$out"
	fail=1
    elif [ -n "$text" ] && ! grep -q "$text" "$out"; then
	echo "FAIL: $desc: stderr lacks '$text'"
	cat "$out"
	fail=1
    else
	echo "ok:   $desc"
    fi
done <<EOF
control: -v does not daemonize, the shim loads#-v#11#0#
fork fails, out of processes##11#1#failed daemonizing
fork fails, out of memory##12#1#failed daemonizing
EOF

rm -f "$out"
exit $fail
