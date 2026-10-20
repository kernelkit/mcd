# nix/analysis/clang-tidy.nix
#
# clang-tidy over the compilation database: every translation unit bear
# recorded (src/*.c, the generated _build/src/cfparse.c, and the lib/
# replacements). --header-filter restricts header diagnostics to the repo.
#
# The DB holds gcc command lines; -Wno-unknown-warning-option keeps clang
# from reporting gcc-only flags such as -Wformat-overflow=2 as diagnostics.
#
# Fails (rather than reporting 0) if clang-tidy could not process a file.
{
  ctx,
  mkReport,
  compileDb,
}:

let
  inherit (ctx) pkgs;
  runner = pkgs.writeShellApplication {
    name = "run-clang-tidy-analysis";
    runtimeInputs = with pkgs; [
      clang-tools
      coreutils
      findutils
      gnugrep
      jq
    ];
    text = ''
      compile_db="$1"
      output_dir="$2"

      echo "=== clang-tidy Analysis (C) ==="

      jq -r '.[] | if (.file | startswith("/")) then .file else "\(.directory)/\(.file)" end' \
        "$compile_db/compile_commands.json" | sort -u > "$output_dir/files.txt"
      echo "translation units: $(wc -l < "$output_dir/files.txt")"

      xargs -a "$output_dir/files.txt" -P "$(nproc)" -I@ \
        clang-tidy \
          -p "$compile_db" \
          --quiet \
          --config='WarningsAsErrors: ""' \
          --extra-arg=-Wno-unknown-warning-option \
          --header-filter='.*/(src|lib)/.*' \
          --checks='-*,bugprone-*,cert-*,clang-analyzer-*,misc-*,readability-*' \
          @ \
        > "$output_dir/report.txt" 2>&1 || true

      if grep -q 'Error while processing' "$output_dir/report.txt"; then
        grep -B5 'Error while processing' "$output_dir/report.txt" >&2
        echo "clang-tidy: a translation unit failed to parse; report is incomplete" >&2
        exit 1
      fi

      grep -c ': warning:\|: error:' "$output_dir/report.txt" > "$output_dir/count.txt" || true
    '';
  };
in
mkReport "clang-tidy" compileDb runner
