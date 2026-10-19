# mcd fuzz harnesses

libFuzzer harnesses for the code in mcd that parses untrusted input:
packets off the wire, the config file, IPC commands, and the output of the
commands mcd runs. They are built by `nix/analysis/fuzz.nix`. See the
Fuzzing section of `nix/README.md` for the targets and how to run them.

| Harness | Entry point | Input |
|---------|-------------|-------|
| `fuzz_igmp` | `accept_igmp()` `src/igmp.c` → `src/iface.c` | mode byte + length-prefixed IPv4/IGMP packets (`packet.h`) |
| `fuzz_mld` | `accept_mld()` `src/mld.c` → `src/iface.c` | mode byte + length-prefixed IPv6/MLD packets; ICMPv6 checksum fixed up unless mode bit `0x40` |
| `fuzz_cfparse` | `config_init()` → `config_parse()` `src/cfparse.y` | an `mcd.conf` |
| `fuzz_ipc` | `ipc_handle()` `src/ipc.c` | one IPC command, as a client writes it to the socket |
| `fuzz_inet_parse` | `inet_parse()` `src/inet.c` | octet-count byte + string |
| `fuzz_bridge_mdb` | `populate()`, `bridge_prop()`, `dumpster()`, … `src/bridge.c` | routine byte + the text/JSON the external command "prints" |

## How the harnesses are put together

- **Real objects.** `fuzz.nix` runs an ordinary out-of-tree autotools
  build with the harness compiler and flags, then links each harness
  against those objects. The only exceptions are `main.o`, `pev.o` and
  `sock.o`, plus any `.c` file the harness `#include`s itself to reach its
  static functions (`cfparse.c`, `ipc.c`, `bridge.c`).
- **`stubs.c`** replaces those three:
  - **Globals.** It provides `main.c`'s globals.
  - **Timers.** Timers go into a table and keep pev's semantics: ids are
    never reused, delete callbacks run, and one-shot timers stay deletable
    after they fire. `fuzz_timers_fire()` fires all pending timers at
    once.
  - **Sending.** `sock_send()` only counts packets. `send_buf` is exactly
    `RECV_BUF_SIZE` on the heap, so ASan catches any overflow while a
    query is being built.
- **Link-time wraps.** `exit()`, `popen()` and `pclose()` are wrapped at
  link time with `-Wl,--wrap=...`:
  - When a harness arms it, `exit()` longjmps back to the harness, so the
    `fatal()` / `yyerror()` paths can be fuzzed.
  - `popen()` returns the bytes set by `fuzz_popen_set()`, so nothing is
    ever executed.
- **Packet framing.** Each IGMP and MLD input brings up a fresh interface,
  `fuzz0` (AF_INET plus its AF_INET6 twin, ifindex 4242), configured from
  the mode byte (`FUZZ_MODE_*` in `fuzz_harness.h`):
  - compat version
  - proxy mode
  - querier disabled
  - raw VLAN
  - whether our address wins elections
  - whether timers fire after each packet

  It then feeds up to 8 packets and tears everything down. Each packet is
  copied into an exact-size heap buffer.
- **Logging.** mcd's logging still formats every message, but nothing is
  printed. `FUZZ_VERBOSE=1` prints the daemon's log to stderr, which helps
  when reading a crash.

## Seeds

`gen_seeds.py` writes the seed corpora at build time. The seeds are valid,
checksummed packets: IGMPv1/2/3 and MLDv1/2 queries, reports, leaves/dones
and v3 group records, plus multi-packet sequences. There are also the
sample and variant `mcd.conf` files, every IPC command, and canned
`bridge mdb show`, `bridge -j` and `ip neigh` output. Seeds must not crash:
`checks.fuzz-replay` runs all of them under ASan/UBSan.

## Adding a harness

1. Write `fuzz_<name>.c` and include `fuzz_harness.h`. Call `fuzz_init()`
   from `LLVMFuzzerInitialize`, and leave no state behind after each input.
2. Add it to `harnesses` in `../fuzz.nix`. List any mcd `.c` file it
   `#include`s under `includes`.
3. Add seeds for it to `gen_seeds.py`.

`nix flake check` builds every harness with gcc against `replay_main.c` and
replays its corpus, so a harness that stops compiling fails the check.

## Known findings and suppressions

The harnesses found these in their first minutes. Each fix adds the input
that reproduced it to `REGRESSIONS` in `gen_seeds.py`; it joins the corpus
as `regress-<name>`, so `checks.fuzz-replay` fails if the bug comes back.

| Harness | Report | Where |
|---------|--------|-------|
| `fuzz_cfparse` | global-buffer-overflow (write): `sscanf("%[.0-9]...")` into the 46-byte global `s1` | `src/cfparse.y` `yylex()`; fixed, `regress-long-dotted-quad` |
| `fuzz_cfparse` | global-buffer-overflow (read): a 1023-byte line with no newline leaves the lexer pointer one past `buf` | `src/cfparse.y` `yytoken()`; fixed, `regress-full-line-no-newline` |
| `fuzz_ipc` | stack-buffer-overflow: `chomp()` walks before the start of a command that is all newlines | `src/defs.h` `chomp()` via `ipc_read()`; fixed, `regress-chomp-all-newlines` |
| `fuzz_bridge_mdb` | NULL `strtok()` result passed to `strlcpy()` / `strtol()` when a `bridge mdb show` line ends after a keyword | `src/bridge.c` `populate()`; fixed, `regress-mdb-line-ends-after-{keyword,vid}` |
| `fuzz_bridge_mdb` (found in review) | heap-buffer-overflow: `strcat()` of every port in a group into the 576-byte `port` list | `src/bridge.c` `populate()`; fixed, `regress-mdb-many-ports-one-group` |
| `fuzz_bridge_mdb` | stack-buffer-overflow (UBSan index 257 out of bounds): the key/value walk trusted the object size, which the non-strict jsmn parser counts keys without values in | `src/bridge.c` `bridge_prop()`; fixed, `regress-json-keys-without-values` |
| `fuzz_bridge_mdb` (found in review) | heap-buffer-overflow: `data[len] = 0` after `fread()` of a full `BUFSIZ` buffer; libFuzzer's default 4096-byte max length never gets there, the replay reads whole files | `src/bridge.c` `bridge_prop()`; fixed, `regress-json-fills-read-buffer` |
| all packet paths | misaligned `struct ip` / `struct ip6_hdr` at `send_buf + ETH_HLEN` | `src/igmp.c` `build_ipv4()`, `src/mld.c`; fixed, the checks are on |

**About the second `cfparse` row.** The stack trace for the `yytoken()`
overread can end in the harness's lexer-drain loop rather than in
`yyparse()`. The parse hit `fatal()` right after the long token, so the
drain made the next `yytoken()` call. In mcd, yacc's lookahead makes that
same call.

**Alignment.** UBSan's alignment check was off at first: it fired on the
first query mcd sent, so the fuzzers never got past it. The misalignment is
harmless on x86 but matters on strict-alignment targets. `sock_init()` now
starts frames `SOCK_BUF_ALIGN` (2) bytes into the packet buffers, so IP
headers are 4-byte aligned, and `stubs.c` lays them out the same way. Every
build checks alignment.
