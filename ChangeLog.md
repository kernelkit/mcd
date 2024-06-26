Change Log
==========

All relevant, user visible, changes are documented in this file.


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

[UNRELEASED]: https://github.com/westermo/querierd/compare/v2.1...HEAD
[v2.1]:       https://github.com/westermo/querierd/compare/v2.0...v2.1
[v2.0]:       https://github.com/westermo/querierd/compare/v1.0...v2.0
[v1.0]:       https://github.com/westermo/querierd/compare/v0.10...v1.0
[v0.10]:      https://github.com/westermo/querierd/compare/v0.9...v0.10
[v0.9]:       https://github.com/westermo/querierd/compare/v0.8...v0.9
[v0.8]:       https://github.com/westermo/querierd/compare/v0.7...v0.8
[v0.7]:       https://github.com/westermo/querierd/compare/v0.6...v0.7
[v0.6]:       https://github.com/westermo/querierd/compare/v0.5...v0.6
[v0.5]:       https://github.com/westermo/querierd/compare/v0.4...v0.5
[v0.4]:       https://github.com/westermo/querierd/compare/v0.3...v0.4
[v0.3]:       https://github.com/westermo/querierd/compare/v0.2...v0.3
[v0.2]:       https://github.com/westermo/querierd/compare/v0.1...v0.2
