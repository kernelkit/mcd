# nix/analysis/compile-db.nix
#
# Self-contained compilation database for clang-tidy and cppcheck.
#
# autotools has no compile_commands.json exporter, so the DB is recorded by
# `bear` around a real out-of-tree build (ctx.configureVpath). A real build
# (not a configure-only pass) is needed anyway: src/cfparse.c is generated
# from src/cfparse.y by bison, and config.h by configure.
#
# The output is a store path containing:
#   $out/                        the source tree, plus _build/ with the
#                                generated config.h and cfparse.c (objects
#                                and binaries removed)
#   $out/compile_commands.json   with the sandbox source root rewritten to
#                                $out, so every 'file', 'directory' and -I
#                                path is readable and immutable
#
# The source sits at $out root so triage's normalize_path, which strips
# /nix/store/<hash>-<name>/, yields repo-relative paths like src/igmp.c.

{ ctx }:

let
  inherit (ctx) pkgs mkAnalysisDrv configureVpath;
in
mkAnalysisDrv {
  name = "compile-db";
  extraNativeBuildInputs = [
    pkgs.bear
    pkgs.jq
  ];

  buildPhase = ''
    runHook preBuild
    srcTop="$PWD"
    ${configureVpath ""}
    bear --output "$srcTop/compile_commands.json" -- make -j"$NIX_BUILD_CORES" -C src
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    find "$srcTop/_build" \( -name '*.o' -o -name mcd -o -name mctl \) -type f -delete
    mkdir -p "$out"
    cp -r "$srcTop"/. "$out/"
    sed "s|$srcTop|$out|g" "$srcTop/compile_commands.json" > "$out/compile_commands.json"

    entries=$(jq length "$out/compile_commands.json")
    echo "compile_commands.json entries: $entries"
    # An empty DB would make every DB-driven tool report 0 findings.
    if [ "$entries" -lt 10 ]; then
      echo "compile-db: only $entries entries; bear did not see the build" >&2
      exit 1
    fi
    runHook postInstall
  '';
}
