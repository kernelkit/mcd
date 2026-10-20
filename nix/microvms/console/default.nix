# nix/microvms/console/default.nix
#
# Serial-console automation for the mcd microVMs (expect, ported from
# xtcp2 by way of partybus). `scripts` bundles the library and drivers in
# one store directory, because drivers source vm-lib.exp from beside
# themselves; the mcd drivers (../scripts/*.exp, the `drivers` argument)
# are installed alongside:
#
#   vm-lib.exp       marker-framed run_out / run / must over a TCP console
#   node-ready.exp   console up, then poll readiness steps
#   node-diag.exp    dump diagnostics when a test fails
#
# `check` (checks.vm-lib-exp) drives all three against a local bash on a
# pty, with no VM: vm-lib-test.exp's library rows, then table rows for the
# two drivers. What it cannot cover - QEMU's chardev, getty autologin, boot
# timing - is covered by `nix run .#vm-check`.
#
{
  pkgs,
  lib,
  # Extra drivers (name -> path) installed next to the library.
  drivers ? { },
}:
let
  scripts = pkgs.runCommand "mcd-console-scripts" { } ''
    mkdir -p $out
    cp ${./vm-lib.exp} $out/vm-lib.exp
    cp ${./vm-lib-test.exp} $out/vm-lib-test.exp
    cp ${./node-ready.exp} $out/node-ready.exp
    cp ${./node-diag.exp} $out/node-diag.exp
    ${lib.concatStrings (lib.mapAttrsToList (n: p: "cp ${p} $out/${n}\n") drivers)}
  '';

  # Driver rows: description, shell command run in the check, expected exit
  # status, and a bash ERE its whole stdout must (or, with !, must not)
  # match. $PORT is the pty shell, $DEAD a port nothing listens on, $FLAG a
  # file the check creates 3s after the rows start.
  row = description: cmd: rc: expect: {
    inherit
      description
      cmd
      rc
      expect
      ;
  };
  driverRows = [
    (row "positive: ready reports the console and each step in order"
      ''expect "$S"/node-ready.exp "$PORT" 30 first true second "test 1 -eq 1"''
      0
      "^MCD_STEP console\nMCD_STEP first\nMCD_STEP second$"
    )
    (row "positive: ready polls a step until it passes"
      ''expect "$S"/node-ready.exp "$PORT" 30 flag "test -f $FLAG"''
      0
      "MCD_STEP flag$"
    )
    (row "negative: a step that never passes fails the driver with exit 1"
      "expect \"$S\"/node-ready.exp \"$PORT\" 8 never false"
      1
      "^MCD_STEP console$"
    )
    (row "negative: steps after a failed step are not reported"
      "expect \"$S\"/node-ready.exp \"$PORT\" 8 never false later true"
      1
      "!MCD_STEP later"
    )
    (row "negative: no console within the budget is exit 2" "expect \"$S\"/node-ready.exp \"$DEAD\" 3" 2
      "!MCD_STEP"
    )
    (row "boundary: no steps is console-only and passes" "expect \"$S\"/node-ready.exp \"$PORT\" 30" 0
      "^MCD_STEP console$"
    )
    (row "boundary: an unpaired step argument is a usage error"
      "expect \"$S\"/node-ready.exp \"$PORT\" 30 lonely"
      2
      "!MCD_STEP"
    )
    (row "positive: diag prints each command under its header"
      ''expect "$S"/node-diag.exp "$PORT" 30 "echo one" "echo two"''
      0
      "^--- \\$ echo one\none\n--- \\$ echo two\ntwo$"
    )
    (row "negative: diag reports a failing command's status and carries on"
      ''expect "$S"/node-diag.exp "$PORT" 30 "(exit 3)" "echo after"''
      0
      "\\(exit 3\\)\n--- \\$ echo after\nafter$"
    )
    (row "corner: diag survives a command with no output"
      ''expect "$S"/node-diag.exp "$PORT" 30 true "echo end"''
      0
      "^--- \\$ true\n--- \\$ echo end\nend$"
    )
    (row "negative: diag with no console is exit 2" "expect \"$S\"/node-diag.exp \"$DEAD\" 3 true" 2
      "!---"
    )

    # make-check.exp against fake build trees ($T/<name>, made below) whose
    # `make check` passes, fails, hangs, or leaves a sanitizer report.
    # MCD_VM_KEEP skips the poweroff, which a pty shell cannot do.
    (row "positive: a passing suite streams its results and exits 0"
      "MCD_VM_KEEP=1 expect \"$S\"/make-check.exp \"$PORT\" 30 60 \"$T\"/pass plain"
      0
      "^PASS: a.sh\nPASS: b.sh\nMCD_CHECK tests=pass exercise=clean findings=0$"
    )
    (row "negative: a failing suite exits 1 and shows the log"
      "MCD_VM_KEEP=1 expect \"$S\"/make-check.exp \"$PORT\" 30 60 \"$T\"/fail plain"
      1
      "FAIL: b.sh(.|\n)*=== /tmp/check.log \\(tail\\) ===(.|\n)*MCD_CHECK tests=fail exercise=clean findings=0$"
    )
    (row "negative: a suite that outlives its budget is incomplete, exit 1"
      "MCD_VM_KEEP=1 expect \"$S\"/make-check.exp \"$PORT\" 30 4 \"$T\"/slow plain"
      1
      "MCD_CHECK tests=fail exercise=incomplete findings=0$"
    )
    (row "negative: asan findings print the reports and fail a passing suite, exit 1"
      "MCD_VM_KEEP=1 expect \"$S\"/make-check.exp \"$PORT\" 30 60 \"$T\"/asan asan"
      1
      "--- a.log\nERROR: AddressSanitizer: fake(.|\n)*MCD_CHECK tests=pass exercise=clean findings=2$"
    )
    (row "negative: asan mode with clean test logs reports no findings"
      "MCD_VM_KEEP=1 expect \"$S\"/make-check.exp \"$PORT\" 30 60 \"$T\"/pass asan"
      0
      "^PASS: a.sh\nPASS: b.sh\nMCD_CHECK tests=pass exercise=clean findings=0$"
    )
    (row "boundary: an unknown mode is a usage error"
      "expect \"$S\"/make-check.exp \"$PORT\" 30 60 \"$T\"/pass bogus"
      2
      "!MCD_CHECK"
    )
    # multicast-topo.exp needs three real guests; here only its argument
    # handling and the no-console path.
    (row "boundary: multicast-topo with too few arguments is a usage error"
      "expect \"$S\"/multicast-topo.exp \"$PORT\" \"$PORT\" 30"
      2
      "!MCD_TOPO"
    )
    (row "negative: multicast-topo with no console is exit 2"
      "expect \"$S\"/multicast-topo.exp \"$DEAD\" \"$DEAD\" \"$DEAD\" /nonexistent 3"
      2
      "!MCD_TOPO"
    )
    (row "negative: make-check with no console is exit 2"
      "expect \"$S\"/make-check.exp \"$DEAD\" 3 60 \"$T\"/pass plain"
      2
      "!MCD_CHECK"
    )
  ];

  # The check's driver (check.sh), a writeShellApplication (shellchecked,
  # with its own tools): starts the pty shell, runs the library tests and
  # the driver rows, and copies the library transcript to OUT.
  checkScript = pkgs.writeShellApplication {
    name = "mcd-vm-lib-check";
    runtimeInputs = with pkgs; [
      bashInteractive
      coreutils
      expect
      gnugrep
      gnused
      gnumake
      socat
      jq
    ];
    text = builtins.readFile ./check.sh;
  };

  check = pkgs.runCommand "mcd-vm-lib-exp" { } ''
    ${lib.getExe checkScript} $out ${scripts} ${pkgs.writeText "vm-lib-rows.json" (builtins.toJSON driverRows)}
  '';
in
{
  inherit scripts check;
}
