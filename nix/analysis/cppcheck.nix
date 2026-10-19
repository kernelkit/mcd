# nix/analysis/cppcheck.nix
#
# cppcheck over the compilation database. --project gives cppcheck the
# exact include paths and defines for every translation unit. One XML run
# (consumed by triage); report.txt is rendered from the same run with
# --template, so the two can never disagree.
#
# Fails (rather than reporting 0) if the XML is not a complete document.
{
  ctx,
  mkReport,
  compileDb,
}:

let
  inherit (ctx) pkgs;
  runner = pkgs.writeShellApplication {
    name = "run-cppcheck-analysis";
    runtimeInputs = with pkgs; [
      cppcheck
      coreutils
      gnugrep
      python3
    ];
    text = ''
      compile_db="$1"
      output_dir="$2"

      echo "=== cppcheck Analysis (C) ==="

      # --project cannot be combined with explicit source args.
      cppcheck \
        --project="$compile_db/compile_commands.json" \
        --enable=all \
        --std=c11 \
        --inline-suppr \
        -j "$(nproc)" \
        --suppress=missingInclude \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        --suppress=checkersReport \
        --xml \
        2> "$output_dir/report.xml" || true

      if ! grep -q '</results>' "$output_dir/report.xml"; then
        tail -20 "$output_dir/report.xml" >&2
        echo "cppcheck: XML report is incomplete" >&2
        exit 1
      fi

      python3 - "$output_dir/report.xml" > "$output_dir/report.txt" <<'EOF'
      import sys, xml.etree.ElementTree as ET
      for e in ET.parse(sys.argv[1]).iter("error"):
          loc = e.find("location")
          where = f'{loc.get("file")}:{loc.get("line")}' if loc is not None else "nofile:0"
          print(f'{where}: {e.get("severity")}: {e.get("msg")} [{e.get("id")}]')
      EOF

      wc -l < "$output_dir/report.txt" > "$output_dir/count.txt"
    '';
  };
in
mkReport "cppcheck" compileDb runner
