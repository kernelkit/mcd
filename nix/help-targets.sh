# Checks mcd-help's targets (nix/targets.nix): each must be a flake
# package or app and be mentioned, as .#<target>, in nix/README.md.
#
# Usage: mcd-help-targets README "OUTPUT..." TARGET...
#
# Built with writeShellApplication (errexit, nounset, pipefail).

readme=$1
outputs=" $2 "
shift 2

fail=0
for t in "$@"; do
    case $outputs in
	*" $t "*) ;;
	*) echo "FAIL: $t: not a flake package or app"; fail=1 ;;
    esac
    if grep -qE "\.#$t([^A-Za-z0-9-]|\$)" "$readme"; then
	echo "ok:   $t"
    else
	echo "FAIL: $t: not in nix/README.md as .#$t"
	fail=1
    fi
done
exit $fail
