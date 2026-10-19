# nix/targets.nix
#
# The flake targets mcd-help lists: the help text is generated from this
# list.
#
# Each section: { title; rows = [ { cmd; desc; target ? null; } ]; }, with
# `target` the package or app name the row runs (null: no single one).
#
# Usage:
#   targets = import ./nix/targets.nix;

[
  {
    title = "Nix build targets (from the repo root; `nix flake show` lists everything)";
    rows = [
      {
        cmd = "nix build";
        desc = "mcd + mctl -> ./result/bin";
      }
      {
        cmd = "nix build .#mcd-clang";
        desc = "built with clang";
        target = "mcd-clang";
      }
      {
        cmd = "nix build .#mcd-werror";
        desc = "built with -Werror";
        target = "mcd-werror";
      }
      {
        cmd = "nix build .#mcd-aarch64";
        desc = "cross: also -armv7l, -riscv64, -ppc64le";
        target = "mcd-aarch64";
      }
      {
        cmd = "nix build .#oci";
        desc = "OCI image (also: oci-debug, oci-<arch>[-debug])";
        target = "oci";
      }
      {
        cmd = "";
        desc = "load with: ./result | docker load";
      }
      {
        cmd = "nix flake check";
        desc = "hermetic checks";
      }
    ];
  }
  {
    title = "Analysis";
    rows = [
      {
        cmd = "nix build .#analysis-quick";
        desc = "clang-tidy + cppcheck + triage";
        target = "analysis-quick";
      }
      {
        cmd = "nix build .#analysis-standard";
        desc = "+ flawfinder, scan-build, gcc-warnings";
        target = "analysis-standard";
      }
      {
        cmd = "nix build .#analysis-deep";
        desc = "+ gcc -fanalyzer, semgrep";
        target = "analysis-deep";
      }
    ];
  }
]
