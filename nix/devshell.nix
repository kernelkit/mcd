# nix/devshell.nix
#
# Development shell for mcd: build tools, the test suite's tools, and the
# analysis/debug tools, plus the mcd-* commands from nix/commands/*.nix:
# writeShellApplications, so each is shellchecked and carries the tools it
# needs, and works in `nix develop -c mcd-build` too.
#
# Usage:
#   devshell = import ./nix/devshell.nix { inherit ctx; };
#   devShells.default = devshell;

{ ctx }:

let
  inherit (ctx) pkgs lib packages;

  # Shared by the commands: the repo root, from git or the current dir.
  root = ''
    mcd_root() {
      git rev-parse --show-toplevel 2>/dev/null || pwd
    }
  '';

  build = import ./commands/build.nix { inherit ctx root; };
  commands = [
    build.mcd-configure
    build.mcd-build
    build.mcd-check
    (import ./commands/clean.nix { inherit pkgs root; })
    (import ./commands/help.nix {
      inherit pkgs lib;
      targets = import ./targets.nix;
    })
  ];
  asciiArt = import ./commands/ascii-art.nix { };

  colored-prompt = ''
    export PS1="\[\033[0;32m\][mcd] \[\033[01;34m\][\u@\h:\w]\$ \[\033[0m\]"
  '';

  welcome = ''
    ${asciiArt}
    echo "  mcd ${ctx.version}, $(gcc --version | head -1)"
    echo "  Tests:     tshark, socat, ethtool, unshare, iproute2"
    echo "  Analysis:  cppcheck, clang-tidy, flawfinder, semgrep, scan-build, bear"
    echo "  Type 'mcd-help' for commands."
  '';
in
pkgs.mkShell {
  packages = packages.allPackages ++ commands;

  # Symbolized ASan/UBSan/libFuzzer traces.
  ASAN_SYMBOLIZER_PATH = "${pkgs.llvm}/bin/llvm-symbolizer";

  shellHook = ''
    # Pin the in-tree build to gcc, matching the Nix package and CI. Set in
    # shellHook because pkgs.clang's setup hook exports CC=clang during shell
    # init; `CC=clang mcd-configure` still works for a clang build.
    export CC=gcc

    ${colored-prompt}
    ${welcome}
  '';
}
