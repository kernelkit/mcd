# nix/cross.nix
#
# Cross-compiled mcd for each non-native target architecture.
#
# mcd is plain autotools + libc with no host code generator, so nixpkgs'
# ready-made cross package sets (pkgs.pkgsCross.<target>) do everything:
# callPackage on package.nix there splices autoreconfHook and bison to
# build-machine tools and stdenv to the cross compiler.
#
# Returns { <arch> = { pkgs; mcd; }; }: the cross package set (for the OCI
# images) and the cross-built mcd.
#
# Usage (from flake.nix, on an x86_64-linux host):
#   cross = import ./nix/cross.nix { inherit ctx; };
#   cross.aarch64.mcd

{ ctx }:

let
  # Short arch names -> pkgsCross targets (lib.systems.examples), which pin
  # the ABI/endianness explicitly:
  #   armv7l  -> hard-float EABI      ppc64le -> 64-bit little-endian ELFv2
  targets = {
    aarch64 = "aarch64-multiplatform";
    armv7l = "armv7l-hf-multiplatform";
    riscv64 = "riscv64";
    ppc64le = "powernv";
  };
in
builtins.mapAttrs (
  _: target:
  let
    pkgs = ctx.pkgs.pkgsCross.${target};
  in
  {
    inherit pkgs;
    mcd = pkgs.callPackage ./package.nix { inherit ctx; };
  }
) targets
