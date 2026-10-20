# nix/analysis/default.nix
#
# Static-analysis entry point for mcd (adapted from the rocm-ernic / xdp2
# framework for this autotools project).
#
# Tools (src/ and lib/):
#   clang-tidy, cppcheck           via the bear-recorded compilation database
#   flawfinder, semgrep            raw-source scanners
#   gcc-warnings, gcc-analyzer     full builds with extra diagnostics
#   clang-analyzer                 scan-build path-sensitive analysis
#
# Aggregate levels (each also runs the triage prioritiser):
#   quick     = clang-tidy + cppcheck
#   standard  = + flawfinder + clang-analyzer + gcc-warnings
#   deep      = + gcc-analyzer + semgrep
#
# Every target is a derivation whose $out holds report.{txt,xml,json} and
# count.txt. Findings never fail a build; an incomplete run does.
#
# Usage:
#   nix build .#analysis-quick | .#analysis-standard | .#analysis-deep
#   nix build .#analysis-cppcheck   (etc. per-tool)

{ ctx }:

let
  inherit (ctx) pkgs lib;
  python = pkgs.python3;

  # ── Compilation database ────────────────────────────────────────
  compileDb = import ./compile-db.nix { inherit ctx; };

  # ── Helpers ─────────────────────────────────────────────────────
  # One report: `script INPUT OUT` fills OUT, where INPUT is the
  # compilation DB (clang-tidy, cppcheck) or the bare source (flawfinder,
  # semgrep).
  mkReport =
    name: input: script:
    pkgs.runCommand "mcd-analysis-${name}" { } ''
      mkdir -p $out
      ${lib.getExe script} ${input} $out
    '';
  toolArgs = { inherit ctx mkReport compileDb; };

  # ── Individual tool targets ─────────────────────────────────────
  clang-tidy = import ./clang-tidy.nix toolArgs;
  cppcheck = import ./cppcheck.nix toolArgs;
  flawfinder = import ./flawfinder.nix toolArgs;
  semgrepTargets = import ./semgrep.nix toolArgs;
  semgrep = semgrepTargets.report;
  gccTargets = import ./gcc.nix { inherit ctx; };
  clang-analyzer = import ./clang-analyzer.nix { inherit ctx; };

  # ── Fuzzing ─────────────────────────────────────────────────────
  fuzzTargets = import ./fuzz.nix { inherit ctx; };
  unit = import ./unit.nix { inherit ctx; };

  # ── Aggregates ──────────────────────────────────────────────────
  # Symlink each tool's output under $out/<name>, run the triage
  # prioritiser, and print a summary table.
  mkAggregate =
    level: tools: summaryExtra:
    let
      # A writeShellApplication (shellchecked, with its own tools):
      # mcd-analysis-<level> OUT fills OUT.
      script = pkgs.writeShellApplication {
        name = "mcd-analysis-${level}";
        runtimeInputs = [
          python
          pkgs.coreutils
        ];
        text = ''
          out=$1
          mkdir -p "$out"
          ${lib.concatMapStringsSep "\n" (t: "ln -s ${t.drv} \"$out\"/${t.name}") tools}

          python3 ${./triage} "$out" --output-dir "$out"/triage

          {
            echo "=== Analysis Summary (${level}) ==="
            echo ""
            ${lib.concatMapStringsSep "\n" (t: ''
              echo "${lib.fixedWidthString 16 " " (t.name + ":")} $(cat ${t.drv}/count.txt) findings"
              if [ -f ${t.drv}/coverage.txt ]; then cat ${t.drv}/coverage.txt; fi
            '') tools}
            echo "${
              lib.fixedWidthString 16 " " "triage:"
            } $(cat "$out"/triage/count.txt 2>/dev/null || echo 0) high-confidence findings"
            echo ""
            ${summaryExtra}
          } > "$out"/summary.txt
          cat "$out"/summary.txt
        '';
      };
    in
    pkgs.runCommand "mcd-analysis-${level}" { } ''
      ${lib.getExe script} $out
    '';

  quickTools = [
    {
      name = "clang-tidy";
      drv = clang-tidy;
    }
    {
      name = "cppcheck";
      drv = cppcheck;
    }
  ];
  standardTools = quickTools ++ [
    {
      name = "flawfinder";
      drv = flawfinder;
    }
    {
      name = "clang-analyzer";
      drv = clang-analyzer;
    }
    {
      name = "gcc-warnings";
      drv = gccTargets.gcc-warnings;
    }
  ];
  deepTools = standardTools ++ [
    {
      name = "gcc-analyzer";
      drv = gccTargets.gcc-analyzer;
    }
    {
      name = "semgrep";
      drv = semgrep;
    }
  ];

  quick =
    mkAggregate "quick" quickTools
      ''echo "Run 'nix build .#analysis-standard' for a broader sweep."'';
  standard =
    mkAggregate "standard" standardTools
      ''echo "Run 'nix build .#analysis-deep' for gcc -fanalyzer + semgrep."'';
  deep = mkAggregate "deep" deepTools ''echo "All analysis tools completed."'';

  # ── Checks ──────────────────────────────────────────────────────
  # Table-driven tests of the triage parsers/filters and the semgrep report
  # validator (nix/analysis/test_runners.py).
  # Only what the tests read, so a harness or rule edit does not rerun them.
  runnerTestSrc = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./triage
      ./test_runners.py
      ./semgrep-report.jq
    ];
  };
  runnerTests =
    pkgs.runCommand "mcd-analysis-runner-tests"
      {
        nativeBuildInputs = [
          python
          pkgs.jq
        ];
      }
      ''
        python3 ${runnerTestSrc}/test_runners.py -v
        touch $out
      '';
in
{
  # The per-tool reports and the aggregate levels, by target name; the
  # flake exposes each as analysis-<name>.
  reports = {
    inherit
      clang-tidy
      cppcheck
      flawfinder
      semgrep
      clang-analyzer
      quick
      standard
      deep
      ;
    inherit (gccTargets) gcc-warnings gcc-analyzer;
  };
  inherit compileDb runnerTests unit;
  semgrepRuleTests = semgrepTargets.ruleTests;
  inherit (fuzzTargets)
    fuzzers
    fuzzRuns
    fuzz-run
    fuzz-replay
    ;
}
