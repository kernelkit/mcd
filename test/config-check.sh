#!/bin/sh
# Verifies mcd -t: checks the configuration file and exits, 0 when
# fine, otherwise non-zero with the error as FILE:LINE: message

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

CONF=/tmp/$NM/config
mkdir -p "/tmp/$NM"

# One row per line: description | config (';' between lines) |
# exit code | expected text in the output
print "Checking configs ..."
fail=0
while IFS='|' read -r desc conf expect text; do
    if [ "$conf" = "MISSING" ]; then
	rm -f "$CONF"
    else
	printf '%s\n' "$conf" | tr ';' '\n' > "$CONF"
    fi

    ../src/mcd -t -f "$CONF" > "/tmp/$NM/out" 2>&1
    rc=$?

    if [ "$rc" -ne "$expect" ]; then
	echo "FAIL: $desc: exit $rc, expected $expect"
	cat "/tmp/$NM/out"
	fail=1
    elif ! grep -qF "$text" "/tmp/$NM/out"; then
	echo "FAIL: $desc: output lacks '$text'"
	cat "/tmp/$NM/out"
	fail=1
    else
	echo "ok:   $desc"
    fi
done <<EOF
plain config|iface eth0 enable igmpv3|0|is ok
comments and blank lines|# comment;;iface eth0 enable|0|is ok
globals|global-query-interval 10;robustness 3;iface eth0 enable|0|is ok
interface not in the system is only a warning|iface nosuch0 enable|0|is ok
include with no match|include /tmp/$NM/nosuch/*.conf;iface eth0 enable|0|is ok
bad value, on line 2|# comment;global-query-interval 0|65|$CONF:2:
mrd interval|mrd-interval 4;iface eth0 enable|0|is ok
mrd interval out of range|mrd-interval 3|65|$CONF:1:
unknown keyword|bogus 1|65|$CONF:1:
vlan out of range|iface eth0 vlan 5000 enable|65|$CONF:1:
missing file|MISSING|66|cannot open
EOF

[ "$fail" -eq 0 ] || FAIL

OK
