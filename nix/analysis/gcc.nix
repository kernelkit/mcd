# nix/analysis/gcc.nix
#
# GCC-based analysis as two full out-of-tree builds:
#   gcc-warnings  extra -W… flags, capture the diagnostics
#   gcc-analyzer  -fanalyzer path-sensitive analysis
#
# Extra flags go in CFLAGS, which automake places after AM_CFLAGS, so they
# override the project's -Wno-* defaults. configureVpath makes every
# diagnostic path absolute; the report keeps in-tree lines only
# (ctx.inTreeDiagnostics).
#
# Fails (rather than reporting 0) if the build did not produce mcd.
{ ctx }:

let
  inherit (ctx)
    lib
    mkAnalysisDrv
    configureVpath
    inTreeDiagnostics
    ;

  gccWarningFlags = [
    "-Wall"
    "-Wextra"
    "-Wpedantic"
    "-Wformat=2"
    "-Wformat-security"
    "-Wshadow"
    "-Wcast-qual"
    "-Wcast-align"
    "-Wwrite-strings"
    "-Wpointer-arith"
    "-Wconversion"
    "-Wsign-conversion"
    "-Wduplicated-cond"
    "-Wduplicated-branches"
    "-Wlogical-op"
    "-Wnull-dereference"
    "-Wdouble-promotion"
    "-Wfloat-equal"
    "-Walloca"
    "-Wvla"
    # C-specific
    "-Wstrict-prototypes"
    "-Wold-style-definition"
    "-Wmissing-prototypes"
    "-Wbad-function-cast"
  ];

  mkGccAnalysisBuild =
    name: extraFlags:
    mkAnalysisDrv {
      inherit name;

      buildPhase = ''
        runHook preBuild
        srcTop="$PWD"
        ${configureVpath ''CFLAGS="-g -O2 ${lib.concatStringsSep " " extraFlags}"''}
        make -j"$NIX_BUILD_CORES" -C src 2>&1 | tee "$NIX_BUILD_TOP/build-output.log" || true
        runHook postBuild
      '';

      installPhase = ''
        ${inTreeDiagnostics name "$NIX_BUILD_TOP/build-output.log"}
        findings=$(wc -l < $out/report.txt)
        echo "$findings" > $out/count.txt
        cp "$NIX_BUILD_TOP/build-output.log" $out/full-build.log
        {
          echo "=== ${name} Analysis ==="
          echo ""
          echo "Extra flags: ${lib.concatStringsSep " " extraFlags}"
          echo "Findings: $findings warnings/errors"
        } > $out/summary.txt
      '';
    };
in
{
  gcc-warnings = mkGccAnalysisBuild "gcc-warnings" gccWarningFlags;
  gcc-analyzer = mkGccAnalysisBuild "gcc-analyzer" [
    "-fanalyzer"
    "-fdiagnostics-plain-output"
  ];
}
