# Hermetic check of the console library and drivers (checks.vm-lib-exp),
# run by mcd-vm-lib-check, a writeShellApplication (errexit, nounset,
# pipefail; shellchecked):
#
#   mcd-vm-lib-check OUT SCRIPTS ROWS
#
# starts a bash on a pty behind a local TCP port, runs vm-lib-test.exp
# against it, then each row of ROWS (JSON: description, cmd, rc, expect;
# see default.nix) and copies the library transcript to OUT. A row's cmd
# runs under bash -c with S (SCRIPTS), T (fake build trees), PORT, DEAD
# and FLAG in the environment.

out=$1
S=$2
rows=$3
# The sandbox has a private network namespace: fixed ports are free.
# Exported for the row commands, which run under bash -c.
export S PORT=17767 DEAD=17768 FLAG=$PWD/flag

# bash on a pty is a faithful stand-in for the guest's autologin
# shell: job control, line editing and terminal echo all depend on
# stdin being a tty. One fresh shell per connection (fork).
socat "TCP-LISTEN:$PORT,reuseaddr,fork" \
  EXEC:'bash --norc --noprofile -i',pty,setsid,ctty,stderr >socat.log 2>&1 &
socat_pid=$!
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then break; fi
  sleep 0.1
done

rc=0
expect "$S"/vm-lib-test.exp "$PORT" >lib.log 2>&1 || rc=$?
grep -E '^(PASS|FAIL|===)' lib.log || true
if [[ $rc -ne 0 ]] || ! grep -q VMLIB_TEST_PASS lib.log; then
  echo "vm-lib.exp regressed (expect exited $rc); transcript:" >&2
  cat lib.log >&2
  exit 1
fi

# Fake build trees for make-check.exp: a Makefile whose `check`
# prints automake-style result lines.
export T=$PWD/trees
mk() {
  mkdir -p "$T/$1"
  printf 'check:\n\t@%s\n' "$2" > "$T/$1/Makefile"
}
mk pass 'echo "PASS: a.sh"; sleep 1; echo "PASS: b.sh"'
mk fail 'echo "PASS: a.sh"; echo "FAIL: b.sh"; exit 1'
mk slow 'echo "PASS: a.sh"; sleep 60'
# Two reports in a.log, one copy in test-suite.log (not counted).
mk asan 'mkdir -p test; printf "ERROR: AddressSanitizer: fake\nx.c:1:2: runtime error: fake\n" > test/a.log; cp test/a.log test/test-suite.log; echo "PASS: a.sh"'

echo "=== drivers ==="
pass=0
fail=0
(sleep 3; touch "$FLAG") &
i=0
while IFS= read -r r; do
  i=$((i + 1))
  desc=$(jq -r .description <<<"$r")
  cmd=$(jq -r .cmd <<<"$r")
  want_rc=$(jq -r .rc <<<"$r")
  want=$(jq -r .expect <<<"$r")
  rc=0
  got=$(bash -c "$cmd" </dev/null 2>"row-$i.err") || rc=$?
  if [[ "$want" == '!'* ]]; then
    re=${want#!}
    if [[ "$got" =~ $re ]]; then matched=0; else matched=1; fi
  else
    if [[ "$got" =~ $want ]]; then matched=1; else matched=0; fi
  fi
  if [[ $rc -eq $want_rc && $matched -eq 1 ]]; then
    echo "PASS: $desc"
    pass=$((pass + 1))
  else
    echo "FAIL: $desc (rc=$rc want=$want_rc)"
    printf '      out: [%s]\n' "$got"
    sed 's/^/      err: /' "row-$i.err"
    fail=$((fail + 1))
  fi
done < <(jq -c '.[]' "$rows")
kill "$socat_pid" 2>/dev/null || true
echo "=== drivers: $pass passed, $fail failed ==="
if (( fail > 0 )); then exit 1; fi
cp lib.log "$out"
