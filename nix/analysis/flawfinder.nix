# nix/analysis/flawfinder.nix
#
# flawfinder source scanner — pattern-matches risky C library calls.
# Works on raw source (no compile DB needed); scans src/ and lib/.
#
# Fails (rather than reporting 0) if flawfinder printed no summary.
{
  ctx,
  mkReport,
  ...
}:

let
  inherit (ctx) pkgs;
  runner = pkgs.writeShellApplication {
    name = "run-flawfinder-analysis";
    runtimeInputs = with pkgs; [
      flawfinder
      coreutils
      gnugrep
    ];
    text = ''
      source_dir="$1"
      output_dir="$2"

      echo "=== flawfinder Analysis ==="

      flawfinder \
        --minlevel=1 \
        --columns \
        --context \
        --singleline \
        "$source_dir/src" \
        "$source_dir/lib" \
        > "$output_dir/report.txt" 2>&1 || true

      # flawfinder prints a summary line "Hits = N"
      if ! findings=$(grep -oP 'Hits = \K[0-9]+' "$output_dir/report.txt"); then
        tail -20 "$output_dir/report.txt" >&2
        echo "flawfinder: no summary line; scan did not complete" >&2
        exit 1
      fi
      echo "$findings" > "$output_dir/count.txt"
    '';
  };
in
mkReport "flawfinder" ctx.srcCode runner
