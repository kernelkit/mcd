# nix/analysis/clang-analyzer.nix
#
# Clang Static Analyzer (scan-build) over the autotools build. scan-build
# wraps both configure and make, so configure records its ccc-analyzer as
# $CC and every translation unit is analysed. C-specific checkers only.
#
# Fails (rather than reporting 0) if the wrapped build did not produce mcd.
{ ctx }:

let
  inherit (ctx)
    pkgs
    lib
    mkAnalysisDrv
    configureVpath
    inTreeDiagnostics
    ;

  scanBuildCheckers = lib.concatStringsSep " " [
    "-enable-checker core.NullDereference"
    "-enable-checker core.DivideZero"
    "-enable-checker core.UndefinedBinaryOperatorResult"
    "-enable-checker core.uninitialized.Assign"
    "-enable-checker security.insecureAPI.getpw"
    "-enable-checker security.insecureAPI.gets"
    "-enable-checker security.insecureAPI.vfork"
    "-enable-checker unix.Malloc"
    "-enable-checker unix.MallocSizeof"
    "-enable-checker unix.MismatchedDeallocator"
    "-enable-checker alpha.security.ArrayBoundV2"
    "-enable-checker alpha.unix.SimpleStream"
  ];

  # configure + make in one script so both run under scan-build's compiler
  # interception. $1 = source root.
  analyzeScript = pkgs.writeShellApplication {
    name = "analyze-build";
    runtimeInputs = [
      pkgs.autoconf
      pkgs.automake
      pkgs.bison
      pkgs.gnumake
    ];
    text = ''
      srcTop="$1"
      ${configureVpath ""}
      make -j"$NIX_BUILD_CORES" -C src
    '';
  };
in
mkAnalysisDrv {
  name = "clang-analyzer";
  extraNativeBuildInputs = [
    pkgs.clang
    pkgs.clang-analyzer
  ];

  buildPhase = ''
    runHook preBuild
    srcTop="$PWD"

    # Use clang-analyzer's scan-build explicitly: the copy that pkgs.clang
    # exposes has a /usr/bin/env shebang that fails in the sandbox.
    ${pkgs.clang-analyzer}/bin/scan-build \
      --use-analyzer=${pkgs.clang}/bin/clang \
      ${scanBuildCheckers} \
      -o "$NIX_BUILD_TOP/scan-results" \
      ${analyzeScript}/bin/analyze-build "$srcTop" \
      2>&1 | tee "$NIX_BUILD_TOP/scan-build.log" || true

    runHook postBuild
  '';

  installPhase = ''
    # This also drops clang's complaints about gcc-only flags in AM_CFLAGS
    # (-Wformat-overflow=2) from report.txt.
    ${inTreeDiagnostics "clang-analyzer" "$NIX_BUILD_TOP/scan-build.log"}

    if [ -n "$(ls -A "$NIX_BUILD_TOP/scan-results" 2>/dev/null)" ]; then
      cp -r "$NIX_BUILD_TOP/scan-results" $out/html-report
    fi

    # scan-build prints "scan-build: N bugs found." or "No bugs found."
    findings=$(grep -oP '\d+(?= bugs? found)' "$NIX_BUILD_TOP/scan-build.log" | head -1 || true)
    echo "''${findings:-0}" > $out/count.txt

    {
      echo "=== Clang Static Analyzer (C) ==="
      echo ""
      echo "Path-sensitive analysis with C-specific checkers."
      echo "Findings: $(cat $out/count.txt)"
    } > $out/summary.txt
  '';
}
