# nix/commands/build.nix
#
# Build-related dev-shell commands for mcd, each a writeShellApplication:
# shellchecked, with exactly the tools it needs on PATH. All of them work
# in-tree from the repo root (autotools builds in place, like CI).
#
# Usage:
#   build = import ./commands/build.nix { inherit ctx root; };
#   [ build.mcd-configure build.mcd-build build.mcd-check ]
{ ctx, root }:

let
  inherit (ctx)
    pkgs
    lib
    packages
    runtimePaths
    ;
in
rec {
  # Generate and run configure. Defaults to the runtime paths the Nix
  # package uses plus --enable-test; extra args are forwarded, e.g.
  #   mcd-configure --with-group=wheel
  #   CC=clang mcd-configure
  mcd-configure = pkgs.writeShellApplication {
    name = "mcd-configure";
    runtimeInputs = [
      pkgs.autoconf
      pkgs.automake
      pkgs.libtool
      pkgs.pkg-config
      pkgs.bison
      pkgs.gnumake
      pkgs.gcc
      pkgs.coreutils
      pkgs.gnused
      pkgs.gnugrep
      pkgs.gawk
      pkgs.git
    ];
    text = ''
      ${root}
      cd "$(mcd_root)"
      ./autogen.sh
      ./configure ${lib.escapeShellArgs runtimePaths} --enable-test "$@"
    '';
  };

  # Build. Configures first if needed. Extra args go to make.
  mcd-build = pkgs.writeShellApplication {
    name = "mcd-build";
    runtimeInputs = [
      mcd-configure
      pkgs.gnumake
      pkgs.gcc
      pkgs.bison
      pkgs.coreutils
      pkgs.git
    ];
    text = ''
      ${root}
      cd "$(mcd_root)"
      if [ ! -f Makefile ]; then
        mcd-configure
      fi
      make -j"$(nproc)" "$@"
    '';
  };

  # Run the network test suite on the host, as CI does. It runs under
  # `unshare -mrun --map-auto`, so it needs unprivileged user namespaces;
  # on Ubuntu with AppArmor first run:
  #   sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
  # `nix run .#vm-check` runs the same suite in a microVM instead.
  mcd-check = pkgs.writeShellApplication {
    name = "mcd-check";
    runtimeInputs = [
      mcd-build
      pkgs.coreutils
      pkgs.git
    ]
    ++ packages.testTools;
    text = ''
      ${root}
      cd "$(mcd_root)"
      mcd-build
      make check "$@"
    '';
  };
}
