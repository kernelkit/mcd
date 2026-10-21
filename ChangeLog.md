Change Log
==========

All relevant, user visible, changes are documented in this file.

[UNRELEASED][]
--------------

### Changes
 - General query when a bridge port starts forwarding, RFC 4541 §2.1.1,
   so hosts behind the port are back in the MDB within the response
   interval instead of at the next periodic query.  Link up, STP
   settling and a port added to the bridge all count, for the bridge
   itself and VLAN interfaces on top of it.  On by default, see
   `topology-query` in mcd.conf(5)
 - Multicast Router Discovery, RFC 4286, IGMP and MLD.  New `iface`
   keyword `mrd on` advertises `mcd` as a multicast router to the
   snooping switches on the LAN, answers their solicitations, and sends
   a termination on the way down.  Off by default.  `mrd-interval`
   sets the advertisement interval.  `mctl show interfaces` has a new
   MRD column, and `mctl show routers` lists the multicast routers
   heard on each interface, with their advertised intervals
 - New `mcd -t` option to check a configuration file and exit, like
   `nginx -t`.  Errors are reported as `FILE:LINE: message`, and it
   runs as a normal user
 - Shell completion for `mctl`, bash and zsh.  The commands come from
   the running daemon, via the new `mctl -C` option.  Installed with
   `make install`, see `--with-bash-completion-dir` and
   `--with-zsh-completion-dir`

### Fixes
 - Fix `-l LEVEL` having no effect in the foreground, `mcd -n` printed
   every message, debug included, whatever the level
 - Fix `mctl show router-ports` and `show igmp json` missing the router
   ports of bridges with a hyphen in their name, e.g. `br-0`
 - Fix shell command injection through bridge names when listing router
   ports.  Linux allows characters like `;` and `$` in interface names
 - Fix IPC error replies, e.g. for an unknown command, never reaching
   the client
 - Fix `mcd` dying of `SIGPIPE` when an IPC client hangs up before
   reading its reply
 - Fix default router timeout (other querier present interval) ignoring
   the configured `robustness`, query and response intervals, it was
   always 255 sec unless `router-timeout` was set.  It is now per
   interface, from the interface's own `query-interval` when set.
   `mctl show interfaces json` has it per interface as
   `router-timeout`, `mctl show` labels the global one as the default
 - Fix group membership interval ignoring the interface's own
   `query-interval`.  With only `query-interval 4` on an interface, a
   group without members stayed for 260 sec, not 18 sec
 - Fix `mcd` exiting 0 when it cannot fork to daemonize
 - Fix `mctl` crashing on a daemon command of more than 32 words
 - Fix timers stopping if an expiry landed exactly on a whole second
 - Fix misaligned IP header access in the packet buffers, a fault on
   strict-alignment targets
 - Fix crashes and buffer overruns on malformed input in the `.conf`
   parser, IPC commands, and `bridge mdb show` / `bridge -j` output, as
   well as for a group on many bridge ports


[v3.0][] - 2026-10-16
---------------------

MLD querier support.  `mcd` now runs one querier per address family on
every enabled interface, so the Linux bridge gets a real querier for
IPv6 too.

> **Note:** MLD is on by default on every enabled interface, use
> `mld off` to keep an interface IGMP only.  `mctl show interfaces`
> has a new Proto column and its JSON output lists both families.

### Changes
 - Add MLD querier, RFC 2710 and RFC 3810.  Queries are sent from the
   link-local address of the interface, with its own election, MLDv2
   to MLDv1 fallback, and the same startup query burst as IGMP
 - New `iface` keywords `mldv1`, `mldv2`, `igmp on|off` and `mld on|off`
 - Add `static-group` per interface, IPv4 and IPv6.  The group is
   joined in the kernel, which answers queries for it like any host, so
   a bridge keeps a permanent host membership for it in the MDB.  The
   memberships survive `SIGHUP`
 - `mctl show interfaces` lists both queriers per interface with a new
   Proto column.  JSON output gains a `family` key per querier and a
   top-level `mld-queriers` list in `show igmp json`
 - Link up and down now reach every entry of an interface, raw VLAN
   entries used to miss them
 - Drop unused `--with-systemd` configure option, no unit file was ever
   installed
 - Add man pages mcd(8), mcd.conf(5) and mctl(8), also available at
   https://man.troglobit.com
 - Rewritten README with figures and worked examples

### Fixes
 - Fix use-after-free when an interface goes down with active group
   timers or a remote querier being tracked
 - Fix potential list corruption when the same interface is configured
   with more than one `vlan`
 - Fix `mctl` writing terminal probe escape sequences to stderr when
   stdout is not a terminal, e.g. when piped to `grep`


[v2.4][] - 2026-04-29
---------------------

### Changes
 - New `mctl show router-ports` command to list multicast router ports grouped
   per bridge, also available as JSON, issue kernelkit/infix#395
 - Improve `mctl show igmp json` multicast-router-ports output; entries are
   now per-bridge objects with `bridge` and `ports` keys
 - RFC3376 §8.6/§8.7: send a startup query burst when assuming the querier
   role.  The querier now sends `Robustness Variable` General Queries at
   `Query Interval / 4` before switching to the normal query cadence, giving
   hosts a much faster initial response, issue #5
 - `mctl` output width now follows the actual terminal width instead of being
   capped at 78 columns; line wrapping is left to the terminal

### Fixes
 - Fix #4: IGMP queries sent with all-zeroes source MAC when an interface
   appears via netlink after the configuration file has already been parsed.
   The hardware address is now re-fetched on every netlink `RTM_NEWLINK` event


[v2.3][] - 2024-04-21
---------------------

### Changes
 - Add IGMP proto support for raw VLAN interfaces
 - New `mctl show mdb` command
 - New `mctl check` command to probe for required tools
 - All `mctl` commands now run `mctl check` internally to ensure
   required tools are available
 - Refactored logging, all log messages affected and may have been
   altered in their output, and severity
 - Add `configure` support for setting IPC socket group ID when `mcd`
   creates its IPC socket, useful to provide `wheel` group access

### Fixes
 - Fix router port detection for VLAN filtering bridges
 - Fix duplicate log message on `send_igmp()` failure
 - Fix `time_t -> int` misuse, found by Coverity Scan
 - Fix uninitialized scalars, found by Coverity Scan
 - Fix resource leak, found by Coverity Scan
 - Fix possible out-of-bounds write, found by Coverity Scan
 - Fix possible out-of-bounds access, found by Coverity Scan
 - Fix build warnings, removing unused functions and adjusting levels


[v2.2][] - 2024-04-17
---------------------

### Changes
 - Document required tools for installation
 - Add support for `MCD_SOCK` environment variable
 - Add helper tools for manual testing on Linux
 - Hide IGMP robustness value from default `mctl show` output
 - Improved output from `mctl show [json]` on multi-bridge systems

### Fixes
 - Fix detection of multicast router ports for `mctl show`
 - Fix detection of IGMP/MLD fast-leave


[v2.1][] - 2024-04-08
---------------------

No daemon changes, only `mctl` output formatting changes.

### Changes
 - Include bridge name in multicast group listings
 - Add support for showing IPv6 and MAC multicast groups
 - Minor format adjustments to IGMP/MLD interface view

### Fixes
 - Enforce `-p` (plain) mode for JSON output.  Fixes spurious
   NUL characters in JSON output, added by mctl formatter


[v2.0][] - 2024-03-21
---------------------

Complete rewrite of core IGMP parts, nothing left of the original
`mrouted` code base.

> **Note:** breaking changes to `.conf` file format!

### Changes
 - Add support for IGMP query interval per interface
 - IGMP global options renamed with `global-` prefix
 - Add support for `include GLOB` directive to .conf parser, see
   bundled sample `mcd.conf` for an example
 - Add support for injecting VLAN tagged frames and receiving frames on
   a VLAN filtering bridge without VLAN interfaces
 - Add support for tracking remote querier's query interval using QQIC
 - Relicense under the ISC license

### Fixes
 - Fix output from usage, `-h`, show correct paths used when
   program identity changes, also add missing options
 - Add missing linefeed in `show igmp json` output
 - Fix parsing of max response time (IGMP code field), changed
   in IGMPv3 to use float encoding for values >= 128
 - Fix JSON output for interface state and querier fields


[v1.0][] - 2024-03-09
---------------------

First release under new stewardship.

### Changes
 - Project forked and renamed to mcd
 - Add JSON output support
 - Renamed setting `proxy-queries` to `proxy-mode`, compat
   for old setting name remains
 - Use lower-case characters for MAC addresses
 - Update documentation, missing `iface` settings

### Fixes
 - Allow fallback to proxy mode if interface has no address
 - Fix coding style
 - Fix build warnings


[v0.10][] - 2023-05-30
----------------------

### Changes
  - Add new passive mode, where no queries are sent

[v0.9][] - 2022-11-24
---------------------

### Fixes
  - Fix memory leak in join handler
  - Fix issue with elements not being removed correctly with TIALQ

[v0.8][] - 2022-11-21
---------------------

### Fixes
  - Fix ports not sorted when running querierctl
  - Fix router ports not showing if vlan doesn't have router port

[v0.7][] - 2022-10-10
---------------------

### Fixes
  - Fix use-after-free on machines with unsigned-by-default chars
  - Fix incorrect VID parsing of MDB entries

[v0.6][] - 2022-07-05
---------------------

### Fixes
  - querierctl: Fix handling of bigger interface indexes in router port parsing

[v0.5][] - 2022-06-20
---------------------

### Changes
  - Add per interface proxy mode
     - Any interface listed as disabled in configuration is considered a
       proxy interface
     - Proxy queries (with source 0.0.0.0) are sent until a real querier is
       detected
     - querierctl shows elected querier for proxy interfaces
  - querierctl: Support for displaying discovered router ports

[v0.4][] - 2022-02-16
---------------------

### Changes
  - Support for adding/removing interfaces at runtime, with new test
  - Add `querierctl` tool, with plain text API over UNIX domain socket
    - Shows elected querier per VLAN, `querierctl show`
	- Shows elected querier timeout
	- Shows which port the elected querier is connected to on bridge
    - Support for displaying `bridge mdb show` in human-friendly format

### Fixes
  - Fix rearming of internal timers, caused wrong querier timeout
    handling and querierd jumping in too early
  - Never allow link-local addresses to win a querier election
  - Never allow 0.0.0.0 address to win a querier election


[v0.3][] - 2022-02-08
---------------------

### Changes
  - Add NETLINK support for link up/down and address add/del
    - Enables seamless operation on interfaces with, e.g., DHCP address
	- Allows for bringing up interfaces long after daemon has started
  - Querier timer now operates per interface, starts when interfaces are
    brought into operation -- configuration remains a global setting
  - Very basic IPC support for querying status from daemon
  - Massive refactor/rename of internal APIs
  - Support for multicast output interface without an address
  - Support for join/leave on interface without an address


[v0.2][] - 2022-02-04
---------------------

### Changes
  - Add proper /etc/querierd.conf support to change:
    - query interval (QI)
	- query response interval (QRI)
	- query last member interval
	- robustness (QRV)
    - router timeout
	- router alert
	- interface on/off with IGMP version
  - Add sample querierd.conf

### Fixes
  - Ignore proxy querys, they must never win elections
  - Query jitter problem of several seconds


v0.1 - 2021-12-01
-----------------

Initial public release.

Limited IGMPv1/v2/v3 querier with hard-coded query interval, etc.  Put
interfaces in a .conf file, whitespace separated to enable querier.

[UNRELEASED]: https://github.com/kernelkit/mcd/compare/v3.0...HEAD
[v3.0]:       https://github.com/kernelkit/mcd/compare/v2.4...v3.0
[v2.4]:       https://github.com/kernelkit/mcd/compare/v2.3...v2.4
[v2.3]:       https://github.com/kernelkit/mcd/compare/v2.2...v2.3
[v2.2]:       https://github.com/kernelkit/mcd/compare/v2.1...v2.2
[v2.1]:       https://github.com/kernelkit/mcd/compare/v2.0...v2.1
[v2.0]:       https://github.com/kernelkit/mcd/compare/v1.0...v2.0
[v1.0]:       https://github.com/kernelkit/mcd/compare/v0.10...v1.0
[v0.10]:      https://github.com/kernelkit/mcd/compare/v0.9...v0.10
[v0.9]:       https://github.com/kernelkit/mcd/compare/v0.8...v0.9
[v0.8]:       https://github.com/kernelkit/mcd/compare/v0.7...v0.8
[v0.7]:       https://github.com/kernelkit/mcd/compare/v0.6...v0.7
[v0.6]:       https://github.com/kernelkit/mcd/compare/v0.5...v0.6
[v0.5]:       https://github.com/kernelkit/mcd/compare/v0.4...v0.5
[v0.4]:       https://github.com/kernelkit/mcd/compare/v0.3...v0.4
[v0.3]:       https://github.com/kernelkit/mcd/compare/v0.2...v0.3
[v0.2]:       https://github.com/kernelkit/mcd/compare/v0.1...v0.2
