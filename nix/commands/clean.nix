# nix/commands/clean.nix
#
# mcd-clean, a writeShellApplication: removes build output and everything
# ./autogen.sh + ./configure generated (the same set .gitignore lists).
#
# Usage:
#   mcd-clean = import ./commands/clean.nix { inherit pkgs root; };
{ pkgs, root }:

pkgs.writeShellApplication {
  name = "mcd-clean";
  runtimeInputs = [
    pkgs.gnumake
    pkgs.coreutils
    pkgs.findutils
    pkgs.git
  ];
  text = ''
    ${root}
    cd "$(mcd_root)"
    if [ -f Makefile ]; then
      make distclean >/dev/null
    fi
    rm -rf autom4te.cache .aux aclocal.m4 configure config.h.in config.h.in~ \
      compile_commands.json
    find . -name Makefile.in -not -path './.git/*' -delete
    echo "Cleaned $(pwd)"
  '';
}
