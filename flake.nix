#
# flake.nix for mcd
#
# A reproducible development environment, hermetic native and cross builds,
# and OCI images for the mcd IGMP/MLD querier. The design is modular: this
# slim flake.nix wires together small single-purpose modules under nix/,
# all sharing one context built in nix/context.nix (see nix/README.md).
# mcd is one callPackage function (nix/package.nix); every variant is an
# .override of it and every cross build a pkgsCross.<target>.callPackage.
#
# Enter the development shell:
#   nix develop                 # then 'mcd-help'
#
# Build mcd + mctl:
#   nix build                   # -> ./result/bin/{mcd,mctl}
#
# Cross-compile (from an x86_64-linux host):
#   nix build .#mcd-aarch64     # also: -armv7l, -riscv64, -ppc64le
#
# Run the static analysis (nix/README.md lists every target):
#   nix build .#analysis-deep && cat result/summary.txt
#
# Fuzz the packet, config and IPC parsers (libFuzzer):
#   nix build .#fuzz && FUZZ_TIME=60 ./result/bin/run-fuzzers
#   nix build .#fuzz-run        # 20 s per harness; also: fuzz-run-<harness>
#
# Build an OCI image (streamLayeredImage: the result is a loader script):
#   nix build .#oci && ./result | docker load   # also: oci-debug, oci-<arch>[-debug]
#
# If flakes are not enabled, prefix commands with:
#   nix --extra-experimental-features 'nix-command flakes' <cmd>
#
# NOTE: flakes only see git-tracked files. After adding or editing files
# under nix/ (or this flake), `git add` them before `nix build`/`nix
# develop`, or the changes are invisible to the evaluation.
#
{
  description = "mcd — IGMP/MLD querier for Linux bridges";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Linux-only: mcd uses AF_PACKET and netlink. eachSystem (not
  # eachDefaultSystem) keeps the flake from generating darwin attributes
  # that could only fail.
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = nixpkgs.lib;

        # Shared build context: sources, package sets, version, configure
        # paths, and mcd itself. Built once, threaded into every module.
        ctx = import ./nix/context.nix { inherit pkgs lib; };

        # The package, and its variants as overrides of the same recipe.
        inherit (ctx) mcd;
        mcd-clang = mcd.override {
          stdenv = pkgs.clangStdenv;
          pnameSuffix = "-clang";
        };
        mcd-werror = mcd.override {
          werror = true;
          pnameSuffix = "-werror";
        };

        devshell = import ./nix/devshell.nix { inherit ctx; };

        # Static analysis (nix/analysis/default.nix): per-tool reports,
        # quick/standard/deep aggregates with triage, and their checks.
        # Every report is a package analysis-<name>.
        analysis = import ./nix/analysis { inherit ctx; };
        analysisPackages = lib.mapAttrs' (n: lib.nameValuePair "analysis-${n}") analysis.reports;

        # OCI images (nix/oci.nix, a callPackage function), minimal and
        # debug: oci[-debug] for the native arch, oci-<arch>[-debug] per
        # cross arch, the tag suffixed with the arch so they don't collide.
        mkOciPair =
          callPackage: mcd: archSuffix:
          lib.mapAttrs'
            (
              variant: suffix:
              lib.nameValuePair "oci${archSuffix}${suffix}" (
                callPackage ./nix/oci.nix { inherit mcd archSuffix variant; }
              )
            )
            {
              minimal = "";
              debug = "-debug";
            };

        # Only from an x86_64-linux host:
        #   cross     mcd per arch ({ pkgs, mcd }); on a native aarch64
        #             host the default package already covers arm64
        isX86_64 = system == "x86_64-linux";
        x86_64 = lib.optionalAttrs isX86_64 (
          let
            cross = import ./nix/cross.nix { inherit ctx; };
          in
          {
            packages =
              lib.mapAttrs' (arch: r: lib.nameValuePair "mcd-${arch}" r.mcd) cross
              // lib.concatMapAttrs (arch: r: mkOciPair r.pkgs.callPackage r.mcd "-${arch}") cross;
          }
        );

        packages = {
          inherit mcd mcd-clang mcd-werror;
          default = mcd;

          # Compilation database (consumed by clang-tidy / cppcheck).
          compile-db = analysis.compileDb;

          # Fuzzing.
          fuzz = analysis.fuzzers; # harnesses + seed corpora + run-fuzzers
          fuzz-run = analysis.fuzz-run; # bounded run, collect crashes
        }
        // lib.mapAttrs' (n: lib.nameValuePair "fuzz-run-${n}") analysis.fuzzRuns
        // analysisPackages
        // mkOciPair pkgs.callPackage mcd ""
        // x86_64.packages or { };
      in
      {
        inherit packages;

        checks = {
          build-gcc = mcd;
          build-clang = mcd-clang;
          build-werror = mcd-werror;
          analysis-runners = analysis.runnerTests;
          semgrep-rules = analysis.semgrepRuleTests;
          fuzz-replay = analysis.fuzz-replay;
          unit = analysis.unit;
        };

        devShells.default = devshell;

        # `nix fmt` with no args formats every tracked .nix file (nixfmt
        # alone would read stdin); with args it formats just those.
        formatter = pkgs.writeShellApplication {
          name = "mcd-fmt";
          runtimeInputs = [
            pkgs.nixfmt
            pkgs.git
          ];
          text = ''
            if [ "$#" -eq 0 ]; then
              git ls-files -z '*.nix' | xargs -0 -r nixfmt
            else
              nixfmt "$@"
            fi
          '';
        };
      }
    );
}
