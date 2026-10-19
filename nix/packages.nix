# nix/packages.nix
#
# Package sets for mcd, split into:
# - buildTools:        autotools + bison for the dev shell's in-tree build
#                      (package.nix takes its own through callPackage)
# - testTools:         what test/*.sh needs at run time (dev shell + microVM)
# - runtimeTools:      what mcd shells out to (ip, bridge, jq) — OCI + microVM
# - devTools:          extra tools for the interactive dev shell only
#
# mcd links against nothing but libc, so there is no buildInputs list.
#
# Usage:
#   packages = import ./nix/packages.nix { inherit pkgs; };

{ pkgs }:

rec {
  # autoreconfHook brings autoconf, automake and libtool for ./autogen.sh;
  # bison provides the yacc AC_PROG_YACC finds for src/cfparse.y.
  buildTools = [
    pkgs.autoreconfHook
    pkgs.bison
  ];

  # mcd runs `ip`, `bridge` and `jq` via popen (src/bridge.c, src/ipc.c).
  runtimeTools = [
    pkgs.iproute2
    pkgs.jq
  ];

  # test/*.sh: namespaces (unshare/nsenter), capture (tshark), IPC (socat),
  # link tweaks (ethtool), plus the runtime tools above.
  testTools = runtimeTools ++ [
    pkgs.util-linux
    pkgs.tshark
    pkgs.socat
    pkgs.ethtool
    pkgs.gnumake
  ];

  # Development-only tools (the dev workflow and the analysis framework).
  devTools = [
    # Debugging / dynamic analysis
    pkgs.gdb
    pkgs.valgrind
    pkgs.strace
    pkgs.ltrace

    # Compilers / tooling
    pkgs.gcc
    pkgs.clang
    pkgs.clang-tools # clang-tidy, clang-format
    pkgs.clang-analyzer # scan-build
    pkgs.llvm # llvm-symbolizer for sanitizer / fuzzer traces
    pkgs.bear # compile_commands.json for autotools

    # Static analysis
    pkgs.cppcheck
    pkgs.flawfinder
    pkgs.semgrep

    # Scripts and VM console drivers
    pkgs.shellcheck
    pkgs.expect

    # Misc
    pkgs.git
    pkgs.nixfmt
  ];

  # Combined list for the dev shell.
  allPackages = buildTools ++ testTools ++ devTools;
}
