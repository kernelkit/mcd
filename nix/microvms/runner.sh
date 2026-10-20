# Host-side runner for the mcd microVMs (see runners.nix): boots the VMs,
# tails their virtio consoles, runs the expect driver under a timeout,
# collects diagnostics if it died early, and prints the verdict.
#
# A writeShellApplication (errexit, nounset, pipefail, linted at
# build), with `config` set ahead of this text to a JSON file:
#   name, description, summary, timeout
#   vms        [ { name, run, serialPort, virtioPort } ], run = microvm-run
#   driver     the expect driver, and driverArgs its arguments
#   nodeDiag   node-diag.exp, and diagCmds the commands it runs per VM
#
# Exit codes: 0 pass, 1 test failure, 2 no console, 3 setup (no KVM, port
# busy, a driver setup step failed), 124 overall timeout.

cfg() { jq -r "$1" "$config"; }

name=$(cfg .name)
description=$(cfg .description)
summary=$(cfg .summary)
driver=$(cfg .driver)
nodeDiag=$(cfg .nodeDiag)
mapfile -t driverArgs < <(cfg '.driverArgs[]')
mapfile -t diagCmds < <(cfg '.diagCmds[]')
mapfile -t vmNames < <(cfg '.vms[].name')
mapfile -t vmRuns < <(cfg '.vms[].run')
mapfile -t vmSerial < <(cfg '.vms[].serialPort')
mapfile -t vmVirtio < <(cfg '.vms[].virtioPort')

TIMEOUT=$(cfg .timeout)
KEEP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    -h|--help)
      echo "usage: $name [--keep] [--timeout <seconds>]"
      echo "  $description"
      echo "  --keep leaves the VM(s) running at the end; attach with"
      for i in "${!vmNames[@]}"; do
        echo "    socat -,raw,echo=0 tcp:127.0.0.1:${vmSerial[$i]}   # ${vmNames[$i]}"
      done
      exit 0
      ;;
    *) echo "$name: unknown argument: $1" >&2; exit 3 ;;
  esac
done

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "$name: /dev/kvm is not accessible (KVM required)" >&2
  exit 3
fi
for p in "${vmSerial[@]}" "${vmVirtio[@]}"; do
  if nc -z 127.0.0.1 "$p" 2>/dev/null; then
    echo "$name: port $p is in use (another mcd VM running?)" >&2
    exit 3
  fi
done

LOGDIR=$(mktemp -d -t mcd-vm-XXXXXX)
echo "================================================"
echo " $name: $description"
echo " logs: $LOGDIR  (qemu-<vm>.log console-<vm>.log driver.log)"
echo "================================================"

vm_pids=()
tail_pids=()
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  for p in "${tail_pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${vm_pids[@]}"; do
    if kill -0 "$p" 2>/dev/null; then
      kill "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

# Every qemu runs in $LOGDIR: link sockets and QMP sockets land there.
for i in "${!vmNames[@]}"; do
  (cd "$LOGDIR" && exec "${vmRuns[$i]}") > "$LOGDIR/qemu-${vmNames[$i]}.log" 2>&1 &
  vm_pids+=("$!")
done

# attach_virtcon <name> <port> <qemu pid>
attach_virtcon() {
  for _ in $(seq 1 60); do
    if nc -z 127.0.0.1 "$2" 2>/dev/null; then
      nc 127.0.0.1 "$2" > "$LOGDIR/console-$1.log" 2>&1 &
      tail_pids+=("$!")
      return 0
    fi
    if ! kill -0 "$3" 2>/dev/null; then
      echo "$name: QEMU for $1 exited during startup:" >&2
      tail -20 "$LOGDIR/qemu-$1.log" >&2
      exit 3
    fi
    sleep 1
  done
}
for i in "${!vmNames[@]}"; do
  attach_virtcon "${vmNames[$i]}" "${vmVirtio[$i]}" "${vm_pids[$i]}"
done

rc=0
MCD_VM_KEEP="$KEEP" timeout "$TIMEOUT" \
  expect "$driver" "${driverArgs[@]}" 2>&1 \
  | tee "$LOGDIR/driver.log" || rc=$?

# A driver that reached its summary line has already dumped what it
# needed and (without --keep) powered its guests off.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ] && ! grep -q "^$summary " "$LOGDIR/driver.log"; then
  echo "=== diagnostics ==="
  for i in "${!vmNames[@]}"; do
    echo "--- ${vmNames[$i]}"
    expect "$nodeDiag" "${vmSerial[$i]}" 30 "${diagCmds[@]}" \
      2>&1 | tee -a "$LOGDIR/diag.log" || true
  done
fi

case "$rc" in
  0)   verdict=PASS ;;
  1)   verdict=FAIL ;;
  2)   verdict="NO CONSOLE" ;;
  124) verdict="TIMEOUT after ${TIMEOUT}s" ;;
  *)   verdict="ERROR (exit $rc)" ;;
esac
echo "================================================"
echo " $name: $verdict"
grep -h "^$summary " "$LOGDIR/driver.log" || true
echo " logs: $LOGDIR"
echo "================================================"

if [ -n "$KEEP" ]; then
  echo "VM(s) left running (--keep). Ctrl-C here stops them."
  for i in "${!vmNames[@]}"; do
    echo "  ${vmNames[$i]}: socat -,raw,echo=0 tcp:127.0.0.1:${vmSerial[$i]}"
  done
  wait "${vm_pids[@]}" || true
fi

exit "$rc"
