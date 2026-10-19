# nix/commands/help.nix
#
# mcd-help, a writeShellApplication printing the dev-shell commands and the
# flake targets, from nix/targets.nix.
#
# Usage:
#   mcd-help = import ./commands/help.nix { inherit pkgs lib targets; };
{
  pkgs,
  lib,
  targets,
}:

let
  # The command, left-aligned in 32 columns, then its description.
  row = r: "  ${r.cmd}${lib.strings.replicate (32 - lib.stringLength r.cmd) " "}${r.desc}";
  section = s: "\n${s.title}:\n" + lib.concatMapStringsSep "\n" row s.rows + "\n";
in
pkgs.writeShellApplication {
  name = "mcd-help";
  text = ''
    cat <<'EOF'
    mcd dev shell — available commands (each a nix-built command):

      mcd-configure [configure args]  autogen + configure (--enable-test, /etc, /run)
      mcd-build     [make args]       Build in-tree (auto-configures if needed)
      mcd-check     [make args]       Run the network test suite (needs userns)
      mcd-clean                       Remove build and autotools output
      mcd-help                        Show this help

    Compiler: CC=gcc by default; `CC=clang mcd-configure` for clang.
    ${lib.concatMapStrings section targets}EOF
  '';
}
