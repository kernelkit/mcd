# nix/analysis/unit.nix
#
# C unit tests of mcd internals the shell tests cannot pin down, e.g. the
# timer arithmetic for a given clock reading. Each nix/analysis/unit/
# test_<name>.c #includes the mcd source it tests, wraps the libc calls
# it fakes (-Wl,--wrap=...), and is built with gcc + ASan/UBSan and run
# once; a failing row fails the build              -> checks.unit
#
# Process tests run the mcd binary itself under an LD_PRELOAD shim
# (unit/<shim>.c) faking the libc calls it cannot make fail in the
# sandbox: test_<name>.sh, a writeShellApplication run as
# test_<name> MCD SHIM.
#
# Tests (table-driven, one row per case):
#   pev        timer expiry and itimer normalization (src/pev.c)
#   daemonize  mcd exits non-zero when it cannot fork (src/main.c)

{ ctx }:

let
  inherit (ctx)
    pkgs
    lib
    version
    srcCode
    mcd
    ;

  unitDir = ./unit;

  # name, and the libc calls the test wraps.
  tests = [
    {
      name = "pev";
      wrap = [
        "clock_gettime"
        "setitimer"
      ];
    }
  ];

  # name, and the shim it runs mcd under.
  procTests = [
    {
      name = "daemonize";
      shim = "fork_fail";
    }
  ];

  # Process test scripts, shellchecked and with their own tools.
  mkProcTest =
    t:
    pkgs.writeShellApplication {
      name = "test_${t.name}";
      runtimeInputs = [
        pkgs.coreutils
        pkgs.gnugrep
      ];
      text = builtins.readFile (unitDir + "/test_${t.name}.sh");
    };

  flags = "${ctx.sanitizerFlags} -g -O1 -Wall -Wextra";
in
pkgs.runCommandCC "mcd-unit-${version}" { } ''
  export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
  export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
  ${lib.concatMapStringsSep "\n" (t: ''
    echo "=== test_${t.name} ==="
    $CC ${flags} -I${srcCode}/src \
      -Wl,${lib.concatMapStringsSep "," (w: "--wrap=${w}") t.wrap} \
      -o test_${t.name} ${unitDir}/test_${t.name}.c
    ./test_${t.name}
  '') tests}
  ${lib.concatMapStringsSep "\n" (t: ''
    echo "=== test_${t.name} ==="
    $CC -shared -fPIC -Wall -Wextra -o lib${t.shim}.so ${unitDir}/${t.shim}.c
    ${lib.getExe (mkProcTest t)} ${mcd}/bin/mcd $PWD/lib${t.shim}.so
  '') procTests}
  touch $out
''
