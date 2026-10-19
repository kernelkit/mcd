# nix/analysis/semgrep.nix
#
# semgrep pattern-based scan of src/ and lib/ with the project's C ruleset
# (semgrep-rules.yaml). Runs fully offline.
#
# Before scanning, each rule fixture in semgrep-tests/ is run with
# `semgrep --test` (a `ruleid:` line must be reported, an `ok:` line must
# not), and a rule that fails to parse fails the build: semgrep otherwise
# skips such a rule with only an entry in the JSON "errors" list, so the
# rule would silently find nothing. The same fixtures are also a flake
# check on their own (`ruleTests`), so a broken rule fails `nix flake check`.
{
  ctx,
  mkReport,
  ...
}:

let
  inherit (ctx) pkgs lib;
  rulesFile = ./semgrep-rules.yaml;
  testsDir = ./semgrep-tests;

  env = ''
    export SEMGREP_ENABLE_VERSION_CHECK=0
    export SEMGREP_SEND_METRICS=off
    export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
    export OTEL_TRACES_EXPORTER=none
    # Keep Semgrep settings/logs writable without changing the caller's HOME.
    semgrep_home="$(mktemp -d)"
    trap 'rm -rf "$semgrep_home"' EXIT
    export SEMGREP_SETTINGS_FILE="$semgrep_home/settings.yml"
    export SEMGREP_LOG_FILE="$semgrep_home/semgrep.log"
  '';

  # One fixture per run: semgrep --test pairs a single target file with the
  # config, and exits non-zero on a missed or unexpected finding. A
  # writeShellApplication: semgrep-rule-tests OUT, results in OUT.
  ruleTestRunner = pkgs.writeShellApplication {
    name = "semgrep-rule-tests";
    runtimeInputs = with pkgs; [
      semgrep
      coreutils
      cacert
    ];
    text = ''
      output_dir="$1"
      ${env}
      for fixture in ${testsDir}/*.c; do
        name=$(basename "$fixture" .c)
        echo "semgrep --test $name"
        semgrep --test --config ${rulesFile} "$fixture" \
          > "$output_dir/rule-test-$name.txt" 2>&1 || {
          cat "$output_dir/rule-test-$name.txt"
          echo "semgrep rule test failed: $name" >&2
          exit 1
        }
      done
    '';
  };

  runner = pkgs.writeShellApplication {
    name = "run-semgrep-analysis";
    runtimeInputs = with pkgs; [
      semgrep
      coreutils
      gnugrep
      cacert
      jq
    ];
    text = ''
      source_dir="$1"
      output_dir="$2"

      echo "=== semgrep Analysis ==="
      ${env}
      ${lib.getExe ruleTestRunner} "$output_dir"

      semgrep \
        --config ${rulesFile} \
        --json \
        --metrics=off \
        --no-git-ignore \
        "$source_dir/src" \
        "$source_dir/lib" \
        > "$output_dir/report.json" 2> "$output_dir/scan-errors.txt" || {
          cat "$output_dir/scan-errors.txt" >&2
          echo "semgrep: scan failed" >&2
          exit 1
        }

      # Validate the structure and the engine errors before counting the
      # findings. semgrep's stderr goes to scan-errors.txt so report.json is
      # only JSON, and report.txt is derived from it rather than a second scan.
      jq -esr -f ${./semgrep-report.jq} "$output_dir/report.json" \
        > "$output_dir/count.txt"
      warnings=$(jq '.errors | length' "$output_dir/report.json")
      if [ "$warnings" -gt 0 ]; then
        echo "PARTIAL COVERAGE: $warnings source parsing warnings; findings are incomplete" \
          | tee "$output_dir/coverage.txt" >&2
      else
        echo 'Complete scan: no source parsing warnings' > "$output_dir/coverage.txt"
      fi
      cat "$output_dir/coverage.txt" > "$output_dir/report.txt"
      jq -r '.errors[] | .message' "$output_dir/report.json" >> "$output_dir/report.txt"
      jq -r '.results[] | "\(.path):\(.start.line): \(.check_id): \(.extra.message)"' \
        "$output_dir/report.json" >> "$output_dir/report.txt"
    '';
  };
in
{
  report = mkReport "semgrep" ctx.srcCode runner;

  ruleTests = pkgs.runCommand "mcd-semgrep-rule-tests" { } ''
    mkdir -p $out
    ${lib.getExe ruleTestRunner} $out
  '';
}
