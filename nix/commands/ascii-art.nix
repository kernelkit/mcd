# nix/commands/ascii-art.nix
#
# ASCII banner printed on entry to `nix develop`. Returns a bash snippet
# spliced into devshell.nix's welcome. Each line is a single-quoted printf
# argument, so backslashes are reproduced verbatim.
{ }:
''
  printf '\033[0;32m%s\033[0m\n' \
    '    _ __ ___   ___ __| |' \
    '   | '"'"'_ ` _ \ / __/ _` |' \
    '   | | | | | | (_| (_| |' \
    '   |_| |_| |_|\___\__,_|' \
    "" \
    '     querier --- query ---> [ br0 ] ---> hosts' \
    '          IGMP / MLD for Linux bridges'
''
