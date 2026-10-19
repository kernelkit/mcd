# nix/analysis/fuzz.nix
#
# libFuzzer harnesses for mcd's untrusted-input parsers. Targets:
#   fuzzers      the harness binaries + seed corpora + run-fuzzers (does not
#                run them)                                  -> .#fuzz
#   fuzzRuns     one bounded run per harness in the sandbox, saving crash
#                inputs and a symbolized repro (always succeeds: the
#                crashes are the deliverable)               -> .#fuzz-run-<name>
#   fuzz-run     all of them, with one summary              -> .#fuzz-run
#   fuzz-replay  every harness built with gcc + ASan/UBSan against
#                replay_main.c and run once over its seed corpus; fails on
#                a build error or a crashing seed           -> checks.fuzz-replay
#
# Harnesses (nix/analysis/fuzz/fuzz_<name>.c, see fuzz/README.md):
#   igmp         accept_igmp() + the querier state machine (src/igmp.c, iface.c)
#   mld          accept_mld() + the querier state machine (src/mld.c, iface.c)
#   cfparse      mcd.conf lexer and grammar (src/cfparse.y)
#   ipc          ipc_handle(): IPC command parsing and handlers (src/ipc.c)
#   inet_parse   inet_parse() (src/inet.c)
#   bridge_mdb   bridge/ip/jq output parsers (src/bridge.c)
#
# Small derivations, so an edit rebuilds only what reads it:
#   objects      mcd built once per toolchain (clang/libFuzzer, gcc/replay)
#                by a real out-of-tree autotools build, so the objects are
#                compiled exactly as mcd's are
#   harness      one per harness and toolchain: fuzz_<name>.c + stubs.c
#                linked against the objects minus main.o, pev.o and sock.o
#                (replaced by fuzz/stubs.c) and minus the .c it #includes
#   corpus       gen_seeds.py's seeds, shared by the runs and replays
#   run, replay  one per harness

{ ctx }:

let
  inherit (ctx)
    pkgs
    lib
    version
    mkAnalysisDrv
    configureVpath
    runtimeDirs
    sanitizerFlags
    ;

  # name, the mcd sources the harness #includes (not linked again), and
  # the fuzz/ headers it needs besides fuzz_harness.h.
  harnesses = [
    {
      name = "igmp";
      includes = [ ];
      headers = [ ./fuzz/packet.h ];
    }
    {
      name = "mld";
      includes = [ ];
      headers = [ ./fuzz/packet.h ];
    }
    {
      name = "cfparse";
      includes = [ "cfparse" ];
      headers = [ ];
    }
    {
      name = "ipc";
      includes = [ "ipc" ];
      headers = [ ];
    }
    {
      name = "inet_parse";
      includes = [ ];
      headers = [ ];
    }
    {
      name = "bridge_mdb";
      includes = [ "bridge" ];
      headers = [ ];
    }
  ];
  names = map (h: h.name) harnesses;
  symbolizer = "${lib.getBin pkgs.llvm}/bin/llvm-symbolizer";

  # Seed corpora, corpus/<harness>/<seed>, from gen_seeds.py and the sample
  # mcd.conf alone: a new seed or REGRESSIONS row re-runs the replay, not
  # a compile.
  fuzzCorpus =
    pkgs.runCommand "mcd-fuzz-corpus-${version}" { nativeBuildInputs = [ pkgs.python3 ]; }
      ''
        python3 ${./fuzz/gen_seeds.py} $out/corpus ${ctx.srcConf}
      '';

  # mcd compiled as for a harness: a real out-of-tree autotools build
  # with the harness compiler and flags, so the objects are built exactly
  # as mcd's are. Installs what the harnesses compile against:
  #   obj/      every mcd and lib/ object but main, pev and sock (replaced
  #             by fuzz/stubs.c)
  #   build/    config.h and the generated src/cfparse.c
  #   src/      the sources, for the harnesses that #include one
  mkObjects =
    {
      name,
      cc,
      cflags,
      extraNativeBuildInputs ? [ ],
    }:
    mkAnalysisDrv {
      name = "${name}-objects";
      inherit extraNativeBuildInputs;
      hardeningDisable = [ "fortify" ];

      buildPhase = ''
        runHook preBuild
        srcTop="$PWD"
        ${configureVpath ''CC=${cc} CFLAGS="${cflags}"''}
        make -j"$NIX_BUILD_CORES" -C src
        runHook postBuild
      '';

      installPhase = ''
        mkdir -p $out/obj $out/build/src
        ls "$srcTop"/_build/src/mcd-*.o "$srcTop"/_build/lib/*.o \
          | grep -v -e '/mcd-main\.o$' -e '/mcd-pev\.o$' -e '/mcd-sock\.o$' \
          | xargs cp -t $out/obj
        cp "$srcTop"/_build/config.h $out/build/
        cp "$srcTop"/_build/src/*.[ch] $out/build/src/
        cp -r "$srcTop"/src $out/src
      '';
    };

  # One harness linked against `objs`: fuzz_<name>.c, stubs.c and the
  # headers it uses (only those, so editing one harness rebuilds only it),
  # plus `extraSrc` (e.g. replay_main.c). -> $out/bin/fuzz_<name>.
  wrapFlags = "-Wl,--wrap=exit,--wrap=popen,--wrap=pclose";
  mkHarness =
    {
      objs,
      cc,
      cflags,
      extraSrc ? [ ],
      extraNativeBuildInputs ? [ ],
    }:
    h:
    let
      src = lib.fileset.toSource {
        root = ./fuzz;
        fileset = lib.fileset.unions (
          [
            (./fuzz + "/fuzz_${h.name}.c")
            ./fuzz/stubs.c
            ./fuzz/fuzz_harness.h
          ]
          ++ h.headers
          ++ extraSrc
        );
      };
      # Same preprocessor setup as src/Makefile.am, plus the build tree
      # for config.h and the generated cfparse.c.
      cppFlags = lib.concatStringsSep " " [
        "-DHAVE_CONFIG_H"
        "-I${objs}/build"
        "-I${objs}/build/src"
        "-I${objs}/src"
        "-I${src}"
        "-D_BSD_SOURCE"
        "-D_DEFAULT_SOURCE"
        "-D_GNU_SOURCE"
        ''-DSYSCONFDIR=\"${runtimeDirs.sysconfdir}\"''
        ''-DRUNSTATEDIR=\"${runtimeDirs.runstatedir}\"''
        ''-DPRESERVEDIR=\"${runtimeDirs.localstatedir}/lib\"''
      ];
      objFilter = lib.concatMapStrings (i: " -e '/mcd-${i}\\.o$'") h.includes;
    in
    pkgs.runCommandCC "mcd-fuzz_${h.name}-${cc}"
      {
        nativeBuildInputs = extraNativeBuildInputs;
        hardeningDisable = [ "fortify" ];
      }
      ''
        objs=$(ls ${objs}/obj/*.o ${lib.optionalString (h.includes != [ ]) "| grep -v${objFilter}"})
        mkdir -p $out/bin
        # shellcheck disable=SC2086
        ${cc} ${cflags} ${cppFlags} \
          ${src}/fuzz_${h.name}.c ${src}/stubs.c \
          ${lib.concatMapStringsSep " " (f: "${src}/${baseNameOf f}") extraSrc} \
          $objs ${wrapFlags} -o $out/bin/fuzz_${h.name}
      '';

  # clang + libFuzzer: the fuzzers.
  libFuzzerFlags = "${sanitizerFlags} -g -O1 -fno-omit-frame-pointer";
  clangObjs = mkObjects {
    name = "fuzz";
    cc = "clang";
    extraNativeBuildInputs = [ pkgs.clang ];
    cflags = "-fsanitize=fuzzer-no-link ${libFuzzerFlags} -Wno-unknown-warning-option";
  };
  clangHarness = lib.genAttrs' harnesses (
    h:
    lib.nameValuePair h.name (
      mkHarness {
        objs = clangObjs;
        cc = "clang";
        extraNativeBuildInputs = [ pkgs.clang ];
        cflags = "-fsanitize=fuzzer ${libFuzzerFlags}";
      } h
    )
  );

  # gcc + ASan/UBSan, plain main(): keeps the harnesses building with the
  # other toolchain and the seed corpora crash-free.
  replayFlags = "${sanitizerFlags} -g -O1";
  gccObjs = mkObjects {
    name = "fuzz-replay";
    cc = "gcc";
    cflags = replayFlags;
  };
  replayHarness = lib.genAttrs' harnesses (
    h:
    lib.nameValuePair h.name (
      mkHarness {
        objs = gccObjs;
        cc = "gcc";
        cflags = replayFlags;
        extraSrc = [ ./fuzz/replay_main.c ];
      } h
    )
  );

  # bin/run-fuzzers in a kit. A writeShellApplication so it is
  # shellcheck-checked and self-contained.
  # bashOptions is limited to nounset so the "run each harness, never fail
  # on a crash" behaviour is preserved.
  runFuzzers = pkgs.writeShellApplication {
    name = "run-fuzzers";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
    ];
    bashOptions = [ "nounset" ];
    text = ''
      # Run each fuzzer for FUZZ_TIME seconds (default 60). Crash inputs and
      # per-harness logs land in FUZZ_WORKDIR (default: a temp dir). Pass
      # harness names to run only those. Never fails on a crash: the caller
      # inspects the workdir.
      root="$(cd "$(dirname "$0")/.." && pwd)"
      time="''${FUZZ_TIME:-60}"
      workdir="''${FUZZ_WORKDIR:-$(mktemp -d)}"
      export ASAN_SYMBOLIZER_PATH="${symbolizer}"
      export UBSAN_SYMBOLIZER_PATH="${symbolizer}"
      export ASAN_OPTIONS="abort_on_error=0:detect_leaks=0:symbolize=1"
      export UBSAN_OPTIONS="print_stacktrace=1"

      if [ "$#" -gt 0 ]; then set -- "$@"; else set -- ${lib.concatStringsSep " " names}; fi

      echo "Fuzzing for ''${time}s each; workdir=$workdir"
      for name in "$@"; do
        echo "=== fuzz_$name ==="
        mkdir -p "$workdir/$name"
        cp "$root/corpus/$name"/* "$workdir/$name/" 2>/dev/null || true
        chmod u+w "$workdir/$name"/* 2>/dev/null || true
        "$root/bin/fuzz_$name" \
          -max_total_time="$time" \
          -print_final_stats=1 \
          -artifact_prefix="$workdir/$name/" \
          "$workdir/$name" \
          > "$workdir/$name.log" 2>&1 || true
        crashes=$(find "$workdir/$name" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' -o -name 'oom-*' \) | wc -l)
        echo "  findings: $crashes (log: $workdir/$name.log)"
      done
      echo "$workdir"
    '';
  };

  # A fuzzer kit: the clang harnesses `ns`, the corpus and run-fuzzers,
  # joined as bin/fuzz_<name>, bin/run-fuzzers and corpus/<name>/.
  mkKit =
    name: ns:
    pkgs.symlinkJoin {
      inherit name;
      paths = map (n: clangHarness.${n}) ns ++ [
        fuzzCorpus
        runFuzzers
      ];
    };
  fuzzers = mkKit "mcd-fuzzers-${version}" names;

  # Bounded run: exercise a harness briefly, collect its crash inputs and a
  # symbolized reproduction of each. Always succeeds.
  runSeconds = 20;

  # mcd-fuzz-run KIT OUT NAME...: runs KIT's harnesses NAME..., then copies
  # the logs, the crash inputs and a symbolized repro of each into OUT,
  # with one summary row per harness in OUT/rows.txt and the total in
  # OUT/count.txt. A writeShellApplication (shellchecked, its own tools).
  fuzzRunScript = pkgs.writeShellApplication {
    name = "mcd-fuzz-run";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
    ];
    text = ''
      kit=$1
      out=$2
      shift 2
      export FUZZ_TIME=${toString runSeconds}
      export FUZZ_WORKDIR="$PWD/work"
      mkdir -p "$FUZZ_WORKDIR" "$out"
      "$kit"/bin/run-fuzzers "$@" || true
      work="$FUZZ_WORKDIR"

      total=0
      for name in "$@"; do
        found=$(find "$work/$name" -maxdepth 1 \( -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' -o -name 'oom-*' \) || true)
        n=$(printf '%s' "$found" | grep -c . || true)
        total=$((total + n))
        execs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$work/$name.log" | grep -o '[0-9]*$' || true)
        cov=$(grep -o 'cov: [0-9]*' "$work/$name.log" | tail -1 || true)
        printf '  %-12s %s finding(s)  [%s, %s runs]\n' "$name:" "$n" "''${cov:-cov: ?}" "''${execs:-?}" \
          >> "$out/rows.txt"

        cp "$work/$name.log" "$out/$name.log" 2>/dev/null || true
        if [ "$n" -gt 0 ]; then
          mkdir -p "$out/crashes/$name"
          printf '%s\n' "$found" | xargs -r cp -t "$out/crashes/$name/"
          first=''${found%%$'\n'*}
          ASAN_SYMBOLIZER_PATH="${symbolizer}" \
          ASAN_OPTIONS="symbolize=1:detect_leaks=0:abort_on_error=0" \
            "$kit/bin/fuzz_$name" "$first" \
            > "$out/crashes/$name/repro.txt" 2>&1 || true
        fi
      done
      echo "$total" > "$out/count.txt"
      cat "$out/rows.txt"
    '';
  };

  # One bounded run per harness, so they run in parallel and a harness
  # edit re-runs only its own.                     -> .#fuzz-run-<name>
  fuzzRuns = lib.genAttrs names (
    n:
    pkgs.runCommand "mcd-fuzz-run-${n}-${version}" { } ''
      ${lib.getExe fuzzRunScript} ${mkKit "mcd-fuzzer-${n}" [ n ]} $out ${n}
    ''
  );

  # mcd-fuzz-summary OUT RUN...: joins per-harness runs into OUT as
  # <harness>.log, crashes/<harness>/, summary.txt and count.txt.
  fuzzSummaryScript = pkgs.writeShellApplication {
    name = "mcd-fuzz-summary";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      out=$1
      shift
      mkdir -p "$out"
      total=0
      for run in "$@"; do
        cp "$run"/*.log "$out"/ 2>/dev/null || true
        if [ -d "$run/crashes" ]; then
          mkdir -p "$out/crashes"
          cp -r "$run"/crashes/. "$out/crashes/"
        fi
        total=$((total + $(cat "$run/count.txt")))
      done
      {
        echo "=== Fuzzing summary (${toString runSeconds}s per harness) ==="
        echo ""
        for run in "$@"; do cat "$run/rows.txt"; done
        echo ""
        echo "Total findings: $total"
        echo ""
        echo "Inputs + symbolized repro under crashes/<harness>/; full logs: <harness>.log."
      } > "$out/summary.txt"
      echo "$total" > "$out/count.txt"
      cat "$out/summary.txt"
    '';
  };

  fuzz-run = pkgs.runCommand "mcd-fuzz-run-${version}" { } ''
    ${lib.getExe fuzzSummaryScript} $out ${lib.concatMapStringsSep " " (n: fuzzRuns.${n}) names}
  '';

  # Each gcc harness run once over its seed corpus; fails on a crashing
  # seed. One derivation per harness, joined for the check.
  fuzzReplays = lib.genAttrs names (
    n:
    pkgs.runCommand "mcd-fuzz-replay-${n}-${version}" { } ''
      export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
      export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
      ${replayHarness.${n}}/bin/fuzz_${n} ${fuzzCorpus}/corpus/${n}
      touch $out
    ''
  );
  fuzz-replay = pkgs.linkFarm "mcd-fuzz-replay-${version}" fuzzReplays;
in
{
  inherit
    fuzzers
    fuzzRuns
    fuzz-run
    fuzz-replay
    ;
}
