# Nix flake: dev shell, builds, analysis, fuzzing and VM tests for mcd

This flake gives mcd a reproducible development environment, hermetic native
and cross builds, OCI container images, a suite of static, dynamic and fuzz
analysis targets, and KVM microVM integration tests: the real `make check`
network suite run as root inside a guest, and a three-VM multicast topology. The design is modular: a
slim top-level `flake.nix` wires together small single-purpose modules under
`nix/`, all sharing one context (`ctx`) built in `nix/context.nix`.

> **Status.** Everything described here is built and tested; the
> [Roadmap](#roadmap) lists the phases and the bugs found so far.

## New to Nix?

[Nix](https://nixos.org) is a package manager that builds software in
isolation from pinned inputs. `nix develop` drops you into a shell with the
exact compilers and tools this project needs, with nothing installed
system-wide, and `nix build` produces the identical binary on any machine.

**Install Nix** (multi-user, recommended):

```
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Single-user (no root, e.g. in a container): use `--no-daemon` instead. Full
instructions: <https://nix.dev/install-nix>.

**Enable flakes** (once). Add this line to `/etc/nix/nix.conf` (or
`~/.config/nix/nix.conf`):

```
experimental-features = nix-command flakes
```

…or prefix each command with
`--extra-experimental-features 'nix-command flakes'`.

**Two commands to get started**, from the repo root:

```
nix develop                 # enter the dev shell; type 'mcd-help'
nix build                   # build mcd -> ./result/bin/mcd, ./result/bin/mctl
```

> Flakes only see git-tracked files. After adding or editing files under
> `nix/`, `git add` them before `nix build` / `nix develop`.

## Dev shell & build

```
nix develop                 # gcc, autotools, bison, test + analysis tools; 'mcd-help'
nix build .#mcd             # default package (gcc)  -> ./result/bin/{mcd,mctl}
nix build .#mcd-clang       # same, built with clang (mirrors the CI matrix)
nix build .#mcd-werror      # gcc with -Werror (checks.build-werror)
```

In the dev shell (each a `writeShellApplication`, so also `nix develop -c mcd-build`):

| Command         | What it does                                                    |
|-----------------|-----------------------------------------------------------------|
| `mcd-configure` | `./autogen.sh && ./configure --enable-test …` (args forwarded)  |
| `mcd-build`     | configures if needed, then `make`                               |
| `mcd-check`     | `make check` on the host, as CI does (needs unprivileged userns) |
| `mcd-clean`     | `make distclean` and remove autotools output                    |
| `mcd-help`      | list the commands and every flake target                        |

The shell pins `CC=gcc` to match CI; `CC=clang mcd-configure` switches.

**Variants.** `nix/package.nix` is a `callPackage` function, and every
variant is an `.override` of the one package (`ctx.mcd`), e.g. in
`flake.nix`:

```nix
mcd-clang = mcd.override { stdenv = pkgs.clangStdenv; pnameSuffix = "-clang"; };
mcd-werror = mcd.override { werror = true; pnameSuffix = "-werror"; };
```

The microVM test trees are `override { enableTest = true; installBuildTree
= true; }` (plus `sanitizers` for ASan), and the cross builds call the same
file with `pkgsCross.<target>.callPackage`.

**`-Werror`.** `checks.build-werror` keeps the gcc build warning-free, so a
new warning fails `nix flake check`.

**Configure paths.** The package is configured with `--sysconfdir=/etc`,
`--localstatedir=/var` and `--runstatedir=/run`, so the paths baked into the
binary are the runtime ones (`/etc/mcd.conf`, `/run/mcd.sock`,
`/var/lib/…`), not store paths. Binaries, man pages and docs still install
into `$out`.

**Runtime dependencies.** mcd itself only needs libc, but `mctl show` and
some IPC commands shell out to `ip`, `bridge` (iproute2) and `jq`. The OCI
image and the microVM include them. A bare `nix build` does not wrap them.

**Host `mcd-check`.** The test suite runs under `unshare -mrun --map-auto`
and uses tshark, socat, ethtool and jq, all of which the dev shell provides.
On Ubuntu hosts with AppArmor, set
`sysctl kernel.apparmor_restrict_unprivileged_userns=0` first. The microVM
runner ([below](#microvm-integration-tests)) avoids host setup entirely.

## Cross-compilation

mcd is pure libc, so every nixpkgs cross target should work. Cross outputs are
built on `x86_64-linux` only.

```
nix build .#mcd-aarch64     # aarch64-multiplatform
nix build .#mcd-armv7l      # armv7l-hf-multiplatform
nix build .#mcd-riscv64     # riscv64
nix build .#mcd-ppc64le     # powernv
file result/bin/mcd
```

| Arch     | nixpkgs `lib.systems.examples` | Build | OCI |
|----------|--------------------------------|-------|-----|
| aarch64  | `aarch64-multiplatform`        | ok    | ok (`mcd:3.0-aarch64`) |
| armv7l   | `armv7l-hf-multiplatform`      | ok    | ok (`mcd:3.0-armv7l`)  |
| riscv64  | `riscv64`                      | ok    | ok (`mcd:3.0-riscv64`) |
| ppc64le  | `powernv`                      | ok    | ok (`mcd:3.0-ppc64le`) |

"ok" means it builds and `file` reports the right ELF machine. Cross
binaries are not executed: `doInstallCheck` is skipped automatically when
the build host cannot run the target.

`nix/cross.nix` maps each arch to a nixpkgs `pkgsCross` set and calls
`nix/package.nix` there with `callPackage`, unchanged. `autoreconfHook`
and `bison` are package arguments in `nativeBuildInputs`, so splicing
gives the build machine's copies.

## Container images (OCI)

```
nix build .#oci                       # minimal image, x86_64
nix build .#oci-debug                 # + bash, coreutils
nix build .#oci-aarch64               # cross images: oci-<arch>[-debug]
./result | docker load                # streamLayeredImage: the result is a script
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v ./mcd.conf:/etc/mcd.conf:ro \
  mcd:3.0
docker exec -it <ctr> mctl show       # mctl talks to /run/mcd.sock inside the ctr
```

Images are built with `dockerTools.streamLayeredImage`. Contents:

- mcd and mctl
- jq, and a slim iproute2 (`ip`, `bridge`) built without iptables, BPF or
  python. That keeps curl, openssl and krb5 out of the image (native minimal
  image ≈ 60 MB). It also avoids the iptables → libpcap → rdma-core chain,
  which does not cross-build for armv7l.
- `dockerTools.fakeNss` for `/etc/passwd`/`group`
- an empty `/run`
- the sample `mcd.conf` at `/etc/mcd.conf`

The entrypoint is `mcd -n` (foreground, log to stderr); extra `docker run`
arguments append, e.g. `-l debug`. Tags are `3.0` and `3.0-debug`. Cross
images carry the arch, `3.0-<arch>[-debug]`, so loading one does not replace
the native image.

**Capabilities.** An image cannot grant capabilities. mcd needs `NET_RAW`
for its AF_PACKET sockets and `NET_ADMIN` for netlink and multicast
membership, and it must see the bridge, hence `--network host` (or run it
inside the target network namespace). Use
`podman` (`nix shell nixpkgs#podman`) if docker isn't installed.

## Static analysis

Each tool is a build target that produces a report. The aggregates also run
the triage prioritiser.

```
nix build .#analysis-quick       # clang-tidy + cppcheck + triage
nix build .#analysis-standard    # + flawfinder, clang-analyzer (scan-build), gcc-warnings
nix build .#analysis-deep        # + gcc-analyzer (-fanalyzer), semgrep
cat result/summary.txt
cat result/triage/high-confidence.txt
```

| Target                     | Tool / mode                                              | Input        |
|----------------------------|----------------------------------------------------------|--------------|
| `compile-db`               | `bear -- make` → `compile_commands.json`                 | configured tree |
| `analysis-clang-tidy`      | bugprone, cert, clang-analyzer, misc, readability checks | compile DB   |
| `analysis-cppcheck`        | `--enable=all --std=c11`, text + XML                     | compile DB   |
| `analysis-flawfinder`      | `--minlevel=1`                                           | source       |
| `analysis-semgrep`         | `nix/analysis/semgrep-rules.yaml`, offline               | source       |
| `analysis-clang-analyzer`  | `scan-build ./configure && make`, HTML report            | source       |
| `analysis-gcc-warnings`    | full build with extra `-W…` flags                        | source       |
| `analysis-gcc-analyzer`    | full build with `-fanalyzer`                             | source       |

**Output layout.** Every tool's `$out` has `report.{txt,xml,json}`,
`count.txt`, and optionally `summary.txt`. Aggregates symlink each tool
under `$out/<tool>/` and add `summary.txt` (a count table) and `triage/`.

**Compile DB.** The DB is produced by `bear` during a real build, so it
includes the bison-generated `src/cfparse.c`. The tree is copied into
`$out` and the DB paths are rewritten to point there, so tools that consume
it see a stable, immutable source tree.

**Scope.** Analysis covers `src/` and `lib/`. The vendored `src/jsmn.h` and
`src/queue.h` are filtered out by triage, not hidden from the tools.

**Out-of-tree build.** The build-driven tools (compile DB, gcc, scan-build)
configure in `_build/` by calling `configure` with an absolute path. automake
then passes absolute source paths to the compiler, so every diagnostic strips
cleanly to `src/foo.c`.

**Semgrep rules.** `semgrep-rules.yaml` holds the generic C ruleset from
rocm-ernic, plus one rule specific to mcd: `strtok-result-unchecked`. It flags
a `strtok()` result that reaches a libc string function with no NULL check,
which is the `bridge mdb show` parsing pattern in `src/bridge.c`. Every rule
has a fixture in `semgrep-tests/` with `ruleid:` / `ok:` annotations. Semgrep
reports `PARTIAL COVERAGE` for a handful of files because its C parser
doesn't understand the `queue.h` list macros; those functions are covered by
the other tools.

**Triage** (`nix/analysis/triage/`) does the following:
1. Loads every tool's report into one finding format.
2. Drops excluded checks and out-of-scope paths.
3. Deduplicates by (file, line, check).
4. Scores findings by bug class and cross-tool agreement.
5. Writes `summary.txt`, `high-confidence.txt`, `cross-ref.txt` and `full-report.txt`.

**Failure semantics.** Findings never fail a build. A run that could not
complete does fail. Examples: a build that broke, semgrep rule tests that
failed, or malformed tool output. A "0 findings" result therefore always
means the tool actually ran. Reading and acting on the findings is a later
phase (see [Roadmap](#roadmap)).

## Dynamic analysis

mcd opens AF_PACKET raw sockets, joins multicast groups and needs bridges,
so it cannot be exercised inside the Nix build sandbox. Dynamic analysis is
split into two parts:

1. **Build** (hermetic): the trees are ordinary derivations, configured with
   `--enable-test` and installed whole under `share/mcd/build`.

   ```
   nix build .#mcd-test-tree         # plain build tree (vm-check, vm-check-valgrind)
   nix build .#mcd-asan-test-tree    # ASan + LSan + UBSan tree
   ```

2. **Exercise** (microVM): the runners boot the guest and run the full
   `make check` suite against the chosen tree.

   ```
   nix run .#vm-check-asan        # reports grepped from test/*.log, counted and printed
   nix run .#vm-check-valgrind    # src/mcd wrapped in valgrind --leak-check=full, logs in /tmp/vg
   ```

   For ASan, a finding is a `runtime error:` or `ERROR: *Sanitizer` line in
   a test log, since mcd's stderr goes there. `log_path` is not used:
   gcc's separate libasan and libubsan runtimes ignored it in the guest.
   UBSan's alignment check is on: the packet buffers keep IP headers
   4-byte aligned (`SOCK_BUF_ALIGN`).

   For valgrind, a finding is a log with `ERROR SUMMARY: [1-9]` or
   `definitely lost: [1-9]`. Each run ends with one line:
   `MCD_CHECK tests=<pass|fail> exercise=<clean|incomplete> findings=<n>`.
   Any finding fails the runner (exit 1), even when every test passed, so
   the ASan and valgrind runners are regression tests. A suite that does
   not finish within its budget is `incomplete` and fails it too, so
   `findings=0` can be trusted.

**First results.** The first ASan runs turned up two IPC bugs, both left
for the results phase:
- **SIGPIPE kills the daemon.** mcd does not ignore SIGPIPE or use
  `MSG_NOSIGNAL`. A client that disconnects before reading its reply makes
  the reply `write()` fatal: mcd exits with status 141 and leaves no
  sanitizer report. socat waits only 0.5 s for a reply, so a slow
  `show igmp` under ASan in the VM was enough to trigger it (`ipc.sh`).
  Deterministic repro: SIGSTOP mcd, run `echo "show igmp" | socat -
  UNIX-CONNECT:<sock>`, wait 1.5 s, then SIGCONT.
  Fixed: replies are sent with `MSG_NOSIGNAL`, and
  `test/ipc-disconnect.sh` runs this repro for each reply path. Valgrind
  itself reports no errors across 68 mcd runs.
- **Error replies are lost.** `ipc_handle()` passes the listening socket
  `sd`, not `client`, to `ipc_err()` (`src/ipc.c`). The "No such command"
  text never reaches the client. Fixed; `test/ipc-errors.sh` covers it.

mcd is single-threaded (one `pev` event loop), so there is no ThreadSanitizer
target.

## Fuzzing

The harnesses use libFuzzer, built with clang
`-fsanitize=fuzzer,address,undefined -g -O1`.

Each harness links against mcd objects from a real out-of-tree autotools
build, so they are compiled exactly as mcd is. Three objects are replaced:
`main.o`, `pev.o` and `sock.o`. Their stand-in is
`nix/analysis/fuzz/stubs.c`:
- **Timers.** Timers go into a table that the harness can fire on demand.
- **Sending.** `sock_send()` counts packets instead of sending them.
- **Wrapped calls.** `exit()`, `popen()` and `pclose()` are wrapped with
  `-Wl,--wrap=...`:
  - `fatal()` longjmps back to the harness instead of exiting.
  - External command output comes from the fuzz input, so nothing is
    executed.

| Harness            | Entry point                                   | Covers |
|--------------------|-----------------------------------------------|--------|
| `fuzz_igmp`        | `accept_igmp()` `src/igmp.c`                  | IGMPv1/2/3 queries, reports, leaves, v3 group records, elections and timers (`src/iface.c`) |
| `fuzz_mld`         | `accept_mld()` `src/mld.c`                    | MLDv1/2, hop-by-hop header walk, the same state machine |
| `fuzz_cfparse`     | `config_init()` → `config_parse()` `src/cfparse.y` | `mcd.conf` lexer and yacc grammar |
| `fuzz_ipc`         | `ipc_handle()` `src/ipc.c`, over a UNIX socket | IPC command matching, options, show handlers |
| `fuzz_inet_parse`  | `inet_parse()` `src/inet.c`                   | dotted-quad / prefix parsing |
| `fuzz_bridge_mdb`  | `populate()`, `bridge_prop()`, `dumpster()` `src/bridge.c` | `bridge mdb show`, `bridge -j`/jq JSON, `ip neigh` output |

**Packet harnesses.** Each input starts with a mode byte, which configures a
fresh `fuzz0` interface: compat version, proxy mode, querier disabled, raw
VLAN, whether our address wins elections, and whether timers fire after each
packet. Up to 8 length-prefixed packets follow, each copied into an
exact-size heap buffer so ASan catches overreads. The MLD harness
recomputes the ICMPv6 checksum, unless the mode byte says not to, so the
fuzzer gets past the checksum check. `nix/analysis/fuzz/README.md` has the
details.

```
nix build .#fuzz                         # harness binaries + seed corpora + run-fuzzers
FUZZ_TIME=300 ./result/bin/run-fuzzers   # per-harness time (default 60 s)
./result/bin/run-fuzzers igmp mld        # just these harnesses
nix build .#fuzz-run                     # 20 s per harness in the sandbox
cat result/summary.txt                   # findings in result/crashes/<harness>/, repro.txt
nix build .#fuzz-run-igmp                # one harness's 20 s run
```

**Build layout.** Each piece is its own derivation, so an edit rebuilds
only what it touches:
- the mcd objects, built once per toolchain (clang + libFuzzer, gcc +
  ASan/UBSan for replay);
- one binary per harness, each from just its own `fuzz_<name>.c`, `stubs.c`
  and headers;
- the seed corpus, from `gen_seeds.py`;
- one 20 s run per harness (`fuzz-run-<name>`), which run in parallel;
  `fuzz-run` joins them into the one summary;
- one replay per harness, joined by `checks.fuzz-replay`.

`.#fuzz` joins the clang binaries, the corpus and `run-fuzzers` into one
tree (`bin/`, `corpus/`).

**Corpora.** `nix/analysis/fuzz/gen_seeds.py` writes the seeds at build
time, so the repo carries no binary blobs. They are valid, checksummed
IGMP/MLD packets and multi-packet sequences, the sample and variant
`mcd.conf` files, every IPC command, and canned `bridge`/`ip` output.
`run-fuzzers` copies them into `FUZZ_WORKDIR` (default: a temp dir) and
fuzzes there, so the store copy stays untouched.

**Reproduce a crash.** Run `./result/bin/fuzz_igmp crash-<hash>`. Add
`FUZZ_VERBOSE=1` to see mcd's own log. The dev shell sets
`ASAN_SYMBOLIZER_PATH`, so traces are symbolized.

**Keeping harnesses honest.** `checks.fuzz-replay` builds every harness with
gcc and ASan/UBSan against `fuzz/replay_main.c`, a plain `main()` that runs
each corpus file once. A harness that stops compiling, or a seed that
crashes, fails `nix flake check`.

**First results.** Within the first minutes the harnesses found:
- a global buffer overflow in the config lexer (`sscanf` into `s1`)
- a lexer overread on a 1023-byte line
- a stack underflow in `chomp()`, reachable from any IPC client
- the NULL `strtok()` result in `bridge.c`
- a misaligned IP header overlay when building queries

The list, with locations and fixes, is in `nix/analysis/fuzz/README.md`;
the [Roadmap](#roadmap) table tracks them.

## MicroVM integration tests

The test suite (`test/*.sh`) creates bridges, veth pairs, VLANs and
namespaces, and checks query traffic with tshark. The microVM runs it as root
on a real kernel, with no host privileges beyond `/dev/kvm`.

```
nix run .#vm-check                # boot guest, run make check, exit 0 PASS / 1 FAIL (~1 min)
nix run .#vm-check -- --keep      # leave the VM up for poking (serial: port 23700)
nix build .#microvm               # just the microvm.nix runner
```

```
 host                                     guest (NixOS, qemu_kvm)
 ─────────────────────────────            ─────────────────────────────────
 vm-check (writeShellApplication)
   ├─ microvm-run &  ─────────────────▶  boots; root autologin on ttyS0
   ├─ nc tail  ◀── virtconsole :23701 ──  journal + kernel log  → transcript
   ├─ expect make-check.exp ── :23700 ─▶  ttyS0: cp -a <tree> /tmp/mcd
   │                                      make check & (unshare -mun per test)
   │      ◀── PASS:/FAIL: lines, polled ─  failing test/*.log dumped
   │      ◀── MCD_CHECK tests= ... ──────  sanitizer / valgrind counts
   ├─ on failure: node-diag.exp ───────▶  dmesg, ip -d link, bridge mdb
   └─ trap: poweroff, kill qemu
```

**Guest** (`nix/microvms/mkVm.nix`):

| Setting          | Value |
|------------------|-------|
| Hypervisor       | qemu_kvm, `-cpu host`, 4 vCPU |
| Memory           | 1024 MiB (never exactly 2048, which hangs QEMU) |
| Nix store        | host `/nix/store` shared over 9p |
| NIC              | SLiRP `user` |
| Serial console   | `ttyS0` on `tcp:127.0.0.1:23700`, owned by expect |
| Virtio console   | `hvc0` on `:23701`, tailed into the transcript |
| Login            | root autologin |
| Kernel           | `linuxPackages_latest` |
| Kernel modules   | `bridge veth 8021q dummy` |
| Packages         | both build trees (via `system.extraDependencies`), tshark, socat, ethtool, jq, iproute2, util-linux, make, valgrind |

**Expect console library** (`nix/microvms/console/vm-lib.exp`, namespace
`vmlib`). This is generic and shared with other projects:
- `connect port timeout` opens the TCP socket directly with `spawn -open`.
  There is no socat or nc pty, so commands are not echoed twice.
- `run_out cmd timeout` wraps the command in `MCD_BEGIN_<n>` /
  `MCD_RC_<n>=<rc>` markers and returns `{rc output}`.
- `run` returns the rc only. `must` exits 3 when the command fails.
- `poweroff` shuts the guest down.
- `connect` returns a console id; `use id` makes it current, for drivers
  that own several consoles.

The drivers are `make-check.exp` (the suite), `node-ready.exp` (poll a list of
readiness commands) and `node-diag.exp` (dump diagnostics, always exit 0).

**Exit codes** (runner and drivers): 0 pass, 1 test failure, 2 no console,
3 setup step failed, 124 overall timeout.

The suite's own `TESTS_ENVIRONMENT` is `unshare -mrun --map-auto`. In the
guest it is overridden with `unshare -mun`: the shell is already root, so
the user namespace is dropped, and each test still gets its own mount, UTS
and network namespaces. The tree is copied with `cp -a`, which keeps the
store timestamps, so `make check` rebuilds nothing.

These runners are packages and apps, not checks: the build sandbox has no
`/dev/kvm`. The Expect library itself *is* checked hermetically
(`checks.vm-lib-exp`), against a socat-backed bash pty.

### Multi-VM multicast topology

```
nix run .#vm-topo                 # boot sw, h1, h2; run the scenario (~2 min)
nix run .#vm-topo -- --keep       # leave all three up (serial: 23710 / 23720 / 23730)
nix build .#microvm-topo-sw       # one guest's microvm.nix runner (also -h1, -h2)
```

```
  h1 lan0 ──link1── p1 ┐
  10.0.0.11            sw: br0 10.0.0.10, mcd (mcast_snooping 1, kernel querier off)
  h2 lan0 ──link2── p2 ┘
  10.0.0.2  (rival mcd, lower address)
```

The links are QEMU `-netdev dgram` unix-socket point-to-point pairs. They need
no tap devices, host bridge or sudo, and give deterministic L2. The socket
paths are relative, and the runner starts every qemu in one fresh directory,
so no stale socket from a killed run can fail a bind. Each link NIC is
renamed by MAC (`systemd.network.links`) and left unmanaged by networkd. The
topology guests are smaller (2 vCPU, 768 MiB each) and have no SLiRP uplink. Sizes, ports, MACs and sockets are in
`constants.nix` (`topo`); console ports are 23700 + 10·n.

`multicast-topo.exp` drives all three serial consoles (`vmlib::use` switches
between them). h1 runs a tshark capture for the whole scenario. The steps:

| Group | Asserts |
|-------|---------|
| links | h1 reaches sw; h2 reaches h1 through the bridge |
| querier | mcd on sw is elected (`mctl -j`); h1 sees IGMPv3 and MLDv2 general queries |
| interval | general queries 8–12 s apart with `global-query-interval 10` |
| join | after h1 joins 239.1.2.3 (socat), sw's mdb has it on p1 only, and mcd lists it |
| leave | the leave draws a group-specific query; mcd and the mdb drop the group |
| election | h2's mcd (10.0.0.2) wins; sw sees it as querier and stops querying |
| takeover | h2's mcd is killed; sw resumes within its router-timeout and is querier again |

Each line is `PASS:`, `FAIL:`, or for a known mcd bug `XFAIL:` / `XPASS:`
(the bug is fixed: drop the marker). The first FAIL dumps mcd's log, `mctl
show`, the mdb and links from every node, then stops. The summary is
`MCD_TOPO steps= pass= fail= xfail= xpass=`.

h2 sets no `router-timeout`, so the election step also checks that the
default follows its `global-query-interval 10` (2·10 + 10/2 = 25 s); this was
an XFAIL until the default was computed after the config is read. sw sets
`router-timeout 15` explicitly so the takeover step stays short.

## Checks (`nix flake check`)

Everything here is hermetic and runs without KVM or network privileges:

| Check               | What it does |
|---------------------|--------------|
| `build-gcc`, `build-clang` | the package builds; `mcd -h` / `mctl -h` run |
| `build-werror`       | the gcc build with `-Werror` |
| `analysis-runners`  | `nix/analysis/test_runners.py`: table-driven tests of triage parsers and the report validators |
| `semgrep-rules`     | `semgrep --test` for every fixture in `nix/analysis/semgrep-tests/` |
| `fuzz-replay`       | every harness built with gcc + ASan/UBSan and replayed over its seed corpus |
| `unit`              | table-driven C unit tests of mcd internals (`nix/analysis/unit/test_<name>.c`, gcc + ASan/UBSan), e.g. `pev.c` timer arithmetic for a chosen clock reading; process tests run mcd under an `LD_PRELOAD` shim, e.g. `fork()` failing |
| `vm-lib-exp`        | table-driven tests of the Expect console library |
| `help-targets`      | every target `mcd-help` lists (`nix/targets.nix`) is a flake package or app and is named as `.#<target>` in this README (x86_64, where they all exist) |

**Shell scripts under `nix/` are `writeShellApplication`s.** Each one is
shellchecked when it is built, runs under `errexit`/`nounset`/`pipefail`,
and has exactly the tools its `runtimeInputs` lists on `PATH`. That covers
the dev-shell commands, the analysis runners and aggregates, `run-fuzzers`
and `fuzz-run`, the semgrep rule tests, the unit process tests, the VM
runners, the `vm-lib-exp` driver, and `mcd-valgrind` (the guest's valgrind
wrapper for `src/mcd`). A derivation with shell logic keeps only a one-line
builder that runs its script with `$out`. `mkDerivation` phases and
plain copy builders stay as they are.

`nix fmt` formats every tracked `.nix` file with `nixfmt`.

## Caching

A derivation rebuilds when any of its inputs changes, so each one is given
only the files it reads (`lib.fileset`, in `nix/context.nix`):

| Fileset | Contents | Used by |
|---------|----------|---------|
| `srcAnalysis` | autotools files, `src/`, `lib/`, `man/`, `test/Makefile.am` | the analysis builds, the fuzz objects (`mkAnalysisDrv`) |
| `srcBuild` | `srcAnalysis` + the docs `make install` ships (`README.md`, …) | the package |
| `srcTest`  | `srcBuild` + `test/` | the microVM test trees (`enableTest`) |
| `srcCode`  | `src/`, `lib/` | flawfinder, semgrep |
| `srcConf`  | `mcd.conf` | the fuzz seed corpus |

The guest system does not contain mcd: the VMs see the host store over 9p
and the runner passes the tree's path to the driver, so a source edit
rebuilds the tree, not the NixOS system.

Derivations rebuilt by a one-line edit, over every x86_64 package and
check (`nix build --dry-run`, against the no-edit set):

| Edit | before | after |
|------|-------:|------:|
| `test/basic.sh`                   | 121 | 8   |
| `src/igmp.c`                      | 121 | 127 |
| `nix/analysis/fuzz/fuzz_igmp.c`   | 7   | 8   |
| `nix/analysis/fuzz/gen_seeds.py`  | 7   | 22  |
| `README.md`                       | 121 | 78  |

A source edit rebuilds about as many derivations as before, but smaller
ones. The rise is the fuzz split: one binary, one 20 s run and one replay
per harness. A one-line `fuzz_igmp.c` edit used to rebuild every harness
and rerun all six 20 s campaigns one after another, about 150 s. It now
rebuilds that harness's clang and gcc binaries and reruns its run and
replay, about 22 s. `gen_seeds.py`
reruns every campaign, but they run in parallel. `README.md` is installed
as documentation, so it still rebuilds the packages and OCI images (10
derivations per image), but no longer any analysis build, fuzzer or NixOS
guest.

## Module map

| Path | Purpose |
|------|---------|
| `flake.nix` | inputs (nixpkgs, flake-utils, microvm.nix), wires the modules and outputs |
| `nix/context.nix` | shared `ctx`: pkgs, version, source filesets, package lists, `runtimeDirs`, `configureVpath`, `inTreeDiagnostics`, `mkAnalysisDrv`, and `mcd` itself |
| `nix/packages.nix` | `buildTools`, `testTools`, `runtimeTools`, `devTools` lists |
| `nix/package.nix` | the mcd build, a `callPackage` function; variants are `mcd.override { stdenv, sanitizers, werror, enableTest, installBuildTree, ... }` |
| `nix/devshell.nix` | `nix develop` shell |
| `nix/commands/` | `mcd-*` dev-shell commands (`writeShellApplication`s) and the banner |
| `nix/targets.nix`, `help-targets.sh` | the targets `mcd-help` lists; `checks.help-targets` checks each is a flake output and is in this README |
| `nix/cross.nix` | arch -> `pkgsCross` set, with `package.nix` called in each |
| `nix/oci.nix` | OCI images (minimal / debug), a `callPackage` function, any arch |
| `nix/analysis/default.nix` | `mkReport`, the per-tool reports and quick/standard/deep aggregates (`reports`, each a package `analysis-<name>`) |
| `nix/analysis/*.nix` | one file per tool (compile-db, clang-tidy, cppcheck, flawfinder, semgrep, clang-analyzer, gcc) |
| `nix/analysis/triage/` | Python triage: parsers, filters, scoring, reports |
| `nix/analysis/test_runners.py` | table-driven tests of the triage parsers/filters and `semgrep-report.jq` |
| `nix/analysis/unit.nix`, `unit/` | C unit tests: each `#include`s the mcd source it tests and fakes libc calls with `-Wl,--wrap` |
| `nix/analysis/fuzz.nix`, `fuzz/` | libFuzzer harnesses (per-toolchain objects, per-harness binaries, runs and replays, the seed corpus), `stubs.c`, `gen_seeds.py`, replay main, fuzz README |
| `nix/microvms/` | guest (`mkVm.nix`), constants (ports, memory), host runners: `runners.nix` writes each runner's JSON config for the static `runner.sh` |
| `nix/microvms/console/` | Expect library, generic drivers, hermetic check (rows in `default.nix`, run by `check.sh`) |
| `nix/microvms/scripts/` | mcd-specific Expect drivers (`make-check.exp`, `multicast-topo.exp`) |

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | This design document | done |
| 2 | flake, derivation, dev shell, cross, OCI | done |
| 3 | static analysis, triage, analysis checks | done |
| 4 | fuzz harnesses, corpora, `fuzz-replay` | done |
| 5 | single-VM `vm-check`, Expect library + check, sanitizer/valgrind VM runners | done |
| 6 | multi-VM multicast topology (`vm-topo`) | done |
| 7 | README brought in line with what was built; arch table filled in | done |
| 8 | refactor: `callPackage`/`.override`/`pkgsCross`, filesets, per-harness fuzzing, static runner scripts ([Caching](#caching)) | done |
| later | read and act on the analysis and fuzzing results | next |

**Bugs found** (all in `src/`). Each fix lands with a test that failed
before it: a regression input in the fuzz corpus (`regress-<name>`, replayed
by `checks.fuzz-replay`), a C unit test (`checks.unit`), a `test/*.sh`
case, or a `vm-topo` step.

| Bug | Found by | Section | Status |
|-----|----------|---------|--------|
| shell command injection through bridge names in the router ports query | `analysis-deep` (popen review) | [Static analysis](#static-analysis) | fixed; `test/bridge-names.sh` |
| router ports never listed for a bridge named like `br-0` (invalid jq `.key`) | `test/bridge-names.sh` | [Static analysis](#static-analysis) | fixed; `test/bridge-names.sh` |
| timer expiry left at `tv_nsec` 1000000000 (`>` for `>=`); at a clock reading of exactly the next second it arms an invalid itimer, ignored, and timers stop | `analysis-deep` (clang-tidy widening, on review) | [Checks](#checks-nix-flake-check) | fixed; `checks.unit` (`test_pev`); very unlikely in practice |
| `mctl` heap overflow storing a daemon `help` command of more than 32 words | `analysis-deep` (clang-analyzer leak report, on review) | [Static analysis](#static-analysis) | fixed; `test/mctl-help.sh` |
| mcd exits 0, not running, when it cannot fork to daemonize | `analysis-deep` (gcc-analyzer `dup2` report, on review) | [Checks](#checks-nix-flake-check) | fixed; `checks.unit` (`test_daemonize`) |
| SIGPIPE on an IPC reply kills the daemon | `vm-check-asan` | [Dynamic analysis](#dynamic-analysis) | fixed; `test/ipc-disconnect.sh` |
| `ipc_err()` writes to the listening socket, not the client | `vm-check-asan` | [Dynamic analysis](#dynamic-analysis) | fixed; `test/ipc-errors.sh` |
| default router-timeout ignores `global-query-interval` | `vm-topo` (XFAIL) | [Multi-VM multicast topology](#multi-vm-multicast-topology) | fixed; `test/router-timeout.sh`, `vm-topo` step |
| config lexer global overflow (`sscanf` into `s1`) | `fuzz_cfparse` | [Fuzzing](#fuzzing) | fixed; `regress-long-dotted-quad` |
| config lexer overread on a 1023-byte line | `fuzz_cfparse` | [Fuzzing](#fuzzing) | fixed; `regress-full-line-no-newline` |
| `chomp()` stack underflow from any IPC client | `fuzz_ipc` | [Fuzzing](#fuzzing) | fixed; `regress-chomp-all-newlines` |
| NULL `strtok()` result in `bridge.c` | `fuzz_bridge_mdb` | [Fuzzing](#fuzzing) | fixed; `regress-mdb-line-ends-after-{keyword,vid}` |
| `populate()` port list overflow, more than ~30 ports in a group | code review | [Fuzzing](#fuzzing) | fixed; `regress-mdb-many-ports-one-group` |
| `bridge_prop()` reading past its 256 JSON tokens on an object with keys but no values | `fuzz-run` | [Fuzzing](#fuzzing) | fixed; `regress-json-keys-without-values` |
| `bridge_prop()` NUL written one byte past its buffer on 8 KiB or more of JSON | code review | [Fuzzing](#fuzzing) | fixed; `regress-json-fills-read-buffer` |
| misaligned IP header overlay in `build_ipv4()` | fuzzers, `vm-check-asan` | [Fuzzing](#fuzzing) | fixed; alignment checks on in `fuzz-replay`, `vm-check-asan` |
| `num` set but not used in `populate()` (blocks `-Werror`) | gcc 16 | [Dev shell & build](#dev-shell--build) | fixed; `checks.build-werror` |

The static-analysis reports (`analysis-deep`) are being worked through; the
findings that turned out real are in the table, highest severity first.

## Provenance

The analysis framework (tool wrappers, triage, semgrep rules and validator)
is adapted from the Nix layer of rocm-ernic, which was itself ported from
xdp2. The microVM console library comes from partybus. Files copied from
rocm-ernic keep their original `SPDX-License-Identifier: MIT` /
copyright headers.
