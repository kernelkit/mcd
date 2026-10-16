mcd: IGMP Querier for the Linux Bridge
======================================
[![1][]][2] [![3][]][4] [![5][]][6]

`mcd` is a small daemon that turns a Linux bridge into a proper IGMP
querier.  It sends queries from a real IP address, takes part in querier
elections, falls back from IGMPv3 to v2 or v1 when old gear shows up,
and follows interfaces and addresses as they come and go.  It ships
with `mctl`, a tool that shows what the querier and the bridge are up
to, in plain text or JSON.

![How mcd fits in](doc/overview.svg)

IPv4 (IGMP) is supported today.  IPv6 (MLD) is on the roadmap.

- [Why?](#why)
- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Inspecting with mctl](#inspecting-with-mctl)
- [Building](#building)
- [Testing](#testing)
- [Origin and license](#origin-and-license)


Why?
----

The Linux bridge has IGMP/MLD snooping, with per-VLAN settings and a
built-in querier.  So why run another one?

Because the bridge querier only sends queries from source IP 0.0.0.0.
The bridge lives below your VLAN interfaces, so it cannot know which
address to use, or even what the interfaces are called (`br0.1` or
`vlan1`?).  Proxy queries like that are allowed by the RFCs, but some
PLCs and other industrial devices silently drop them.  Good luck getting
the vendor to fix a ten year old firmware.

Many of these networks have no multicast router either.  They are just
switches, doing their best to keep multicast off low-capacity links.
Without a querier, snooping times out and multicast turns into
broadcast, which is what takes these sites down.

The bridge also lacks version fallback.  Per RFC, a LAN should run
IGMPv3 until a v2 host appears, then drop to v2 for as long as that
host keeps talking.  The bridge has no such fallback.

`mcd` fills that gap.  It queries from the bridge's own addresses,
follows the election rules, and keeps snooping armed on LANs that have
no multicast router.


Features
--------

- Queries go out with the interface address as source, so even picky
  end devices answer them.
- Querier election per RFC 2236 and 3376, lowest IP wins.  When a
  better querier shows up, `mcd` backs off and watches the other
  querier timer.  When it expires, `mcd` takes over again.
- Startup query burst.  On assuming the querier role, `mcd` sends
  `robustness` queries spaced `query-interval / 4` apart, per RFC 3376
  §8.6 and §8.7.  A host that missed the first query gets another one
  within half a minute instead of waiting a full query interval.
- Version fallback.  Starts at IGMPv3, drops to v2 or v1 when such
  hosts appear, and returns when they go quiet.
- Proxy mode, a backup querier that sends from 0.0.0.0 and can never
  win an election.  Used automatically when an interface has no address.
- Raw VLAN mode.  Run a querier directly on a VLAN of a filtering
  bridge, no `vlanN` interface required.
- Static groups, joined in the kernel so they never time out.
- Netlink aware.  Interfaces that appear late, DHCP addresses and link
  flaps are all handled without a restart.
- `mctl` shows interface and querier status, group memberships, router
  ports per bridge, and the bridge MDB in a readable form.  JSON output
  for scripts, a watch mode for humans.
- Plain C, no runtime library dependencies, ISC licensed.

![Querier lifecycle on one interface](doc/querier-timeline.svg)


Quick start
-----------

Build and install, see [Building](#building) for details:

    ./autogen.sh      # only when building from git
    ./configure && make && sudo make install

Enable the querier in `/etc/mcd.conf`, on the bridge itself or on the
VLAN interfaces on top of it:

    iface br0 enable
    iface vlan1 enable
    iface vlan2 enable

Start the daemon, and look at what it does:

    sudo mcd -n -l info
    mctl show

Every interface in the system is probed at start, and again on
`SIGHUP`, which also re-reads the configuration file.


Configuration
-------------

Default file is `/etc/mcd.conf`, override with `-f`.  By default `mcd`
is passive on all interfaces.  The full syntax:

    global-query-interval [1-1024]            # default: 125 sec
    global-response-interval [1-1024]         # default: 10 sec
    global-last-member-interval [1-1024]      # default: 1 sec
    robustness [2-10]                         # default: 2
    router-timeout [1-1024]                   # default: calculated
    no router-alert                           # default: enabled

    iface IFNAME [enable | disable] [vlan [1-4094]]
          [proxy-mode] [igmpv1 | igmpv2 | igmpv3]
          [query-interval [1-1024]] [static-group GROUP ...]

    include /path/to.d/*.conf

### Global settings

| Setting                       | Meaning                                                              |
|-------------------------------|----------------------------------------------------------------------|
| `global-query-interval`       | Seconds between General Queries when elected querier                 |
| `global-response-interval`    | Max response time hosts get, controls how bursty replies are         |
| `global-last-member-interval` | Seconds between group specific queries, `robustness` sets the count  |
| `robustness`                  | Tolerance to lost reports and lost queriers, also the startup burst length |
| `router-timeout`              | Other querier present interval, see below                            |
| `no router-alert`             | Drop the IP Router Alert option from queries                         |
| `include`                     | Read one file, or every file matching a glob, e.g. `/etc/mc.d/*.conf` |

The `router-timeout` is the time `mcd` waits for a silent querier before
taking over.  Left unset, the RFC formula applies:

    robustness * query-interval + response-interval / 2

Setting it by hand overrides the formula.  Some non-compliant devices
need this.  Everyone else should leave it alone.

Router Alert is on by default, for stacks that hard-code the length of
the IP header.  Turn it off only if you know you have to.

### Interface settings

| Flag                 | Meaning                                                               |
|----------------------|-----------------------------------------------------------------------|
| `enable`, `disable`  | Run a querier on the interface, or not.  Default is `disable`         |
| `vlan VID`           | Raw VLAN mode on a filtering bridge, see below                        |
| `proxy-mode`         | Backup querier, source 0.0.0.0, never wins an election                |
| `igmpv1`, `igmpv2`, `igmpv3` | Starting IGMP version.  Default `igmpv3`, with automatic fallback |
| `query-interval N`   | Per interface override of `global-query-interval`                     |
| `static-group GROUP` | Join GROUP on the interface, as a host would, see below               |

The keyword `phyint` is accepted as an alias for `iface`, and the old
`proxy-queries` still works as an alias for `proxy-mode`.

### Enabling the querier

The interface can be a VLAN interface on top of the bridge, or the
bridge itself:

    iface vlan1 enable
    iface br0 enable

Either way, queries use the interface address as source and `mcd`
competes in the election.  Use the bridge directly when it has no VLAN
filtering, or when the VLAN you care about is its untagged default.
For other VLANs of a filtering bridge, see raw VLAN mode below.

`mcd` starts as IGMPv3 and drops to v2 on its own if a legacy host
appears.  To start out in v2 instead:

    iface vlan1 enable igmpv2

### Proxy mode

    iface vlan1 enable proxy-mode

In proxy mode `mcd` sends from 0.0.0.0 and therefore always loses
elections.  It only queries when no real querier is around, which makes
it a safe backup on LANs that normally have a multicast router.

> **Note:** an interface without an IP address runs in proxy mode
> whether you asked for it or not.  When an address shows up, via
> netlink, `mcd` switches to standard mode by itself.

### Raw VLAN mode

A VLAN filtering bridge with no `vlanN` interface on top can still get
a querier.  `mcd` injects tagged frames straight into the bridge, and
is always in proxy mode here:

    iface br0 vlan 42 enable

### Per interface query interval

    global-query-interval 125
    iface vlan1 enable query-interval 30

There is no per interface setting for the other intervals, only
protocol version and query interval.

### Static groups

    iface vlan1 enable static-group 239.1.1.1 static-group 239.1.1.2

`mcd` joins each group in the kernel, which then answers queries for it
like any other host.  On a bridge this gives the group a permanent host
membership in the MDB, so it is always forwarded to the bridge itself.
The membership is dropped when the interface goes down or `mcd` exits.

This does not work in raw VLAN mode, since the kernel cannot join on a
specific VLAN of a bridge.


Inspecting with mctl
--------------------

`mctl` talks to the daemon over a UNIX socket.  Run it without
arguments for an overview:

    $ mctl
    Multicast Overview
    Query Interval (default): 125 sec
    Router Timeout          : 255
    Fast Leave Ports        :
    Router Ports            : eth3
    Flood Ports             :

    Interface       VID  Querier                     State  Interval  Timeout  Ver
    vlan1                192.168.1.1                    Up       125     None    3
    vlan2                192.168.2.1                    Up       125     None    3
    br0              42  0.0.0.0                        Up       125     None    3

    Bridge          VID  Multicast Group       Ports
    br0               2  239.1.1.1             eth3

Commands:

| Command                     | Shows                                              |
|-----------------------------|----------------------------------------------------|
| `show` / `show igmp [json]` | Interfaces and group memberships, the default      |
| `show status [json]`        | Daemon settings and bridge port roles              |
| `show interfaces [json]`    | Querier state per interface                        |
| `show groups [json]`        | IGMP group memberships                             |
| `show router-ports [json]`  | Multicast router ports, grouped per bridge         |
| `show mdb`                  | The bridge MDB, as `bridge mdb show` but readable  |
| `check`                     | Verify that `ip`, `bridge` and `jq` are available  |
| `version`                   | Daemon version                                     |

Useful options:

| Option           | Effect                                                      |
|------------------|-------------------------------------------------------------|
| `-m, --monitor`  | Re-run the command every two seconds, like `watch(1)`       |
| `-p, --plain`    | Plain headings, no terminal control characters              |
| `-t, --no-heading` | Skip table headings, handy for scripts                    |
| `-i, --ident`    | Talk to a daemon started with `-i NAME`                     |
| `-u, --ipc`      | Socket path, also settable with the `MCD_SOCK` variable     |

Output width follows your terminal.  Add `json` to any `show` command
for machine readable output:

    mctl show router-ports json
    [
      {
        "bridge": "br0",
        "ports": [ "eth3" ]
      }
    ]

> **Note:** collecting bridge status needs `jq` and the iproute2 tools
> `ip` and `bridge`.  The BusyBox versions are not enough.  Run
> `mctl check` to confirm.

### Talking to mcd without mctl

The IPC protocol is plain text, one command per connection:

    echo "help" | socat - UNIX-CONNECT:/run/mcd.sock
    echo "show igmp json" | socat - UNIX-CONNECT:/run/mcd.sock

### Daemon options

    mcd [-himnpsv] [-f FILE] [-i NAME] [-l LEVEL] [-p FILE] [-u FILE]

| Option               | Effect                                                     |
|----------------------|------------------------------------------------------------|
| `-f, --config=FILE`  | Configuration file, default `/etc/mcd.conf`                |
| `-i, --ident=NAME`   | Identity, sets the default `.conf`, `.pid` and `.sock` names and the syslog tag |
| `-l, --loglevel=LEVEL` | `none`, `err`, `notice` (default), `info`, `debug`       |
| `-n, --foreground`   | Stay in the foreground, log to stderr                      |
| `-s, --syslog`       | Log to syslog, the default when not in the foreground      |
| `-p, --pidfile=FILE` | PID file, default `/run/mcd.pid`                           |
| `-u, --ipc=FILE`     | IPC socket, default `/run/mcd.sock`                        |

To run several instances, give each one its own `-i NAME` and point
`mctl -i NAME` at the one you want.


Building
--------

`mcd` uses GNU autotools.  From a release tarball:

    ./configure
    make
    sudo make install

From git, run `./autogen.sh` first.  That needs `autoconf`, `automake`
and `bison` (or another yacc).

Options worth knowing:

| Option                 | Effect                                                     |
|------------------------|------------------------------------------------------------|
| `--with-group=NAME`    | Group owner of `/run/mcd.sock`, default `root`.  Use e.g. `wheel` to let admins run `mctl` without `sudo` |
| `--enable-test`        | Build the test suite, see below                            |
| `--prefix=`, `--sysconfdir=` | The usual, defaults are `/usr/local` and `/etc`      |

Configure prints a summary at the end, check it before running `make`.


Testing
-------

The test suite runs in network namespaces, so it needs `unshare`,
`socat`, `jq`, `tshark` and iproute2.  Build with `--enable-test` and
run:

    make check

For poking at `mcd` by hand there are helper scripts in `util/` that
set up a namespace with a bridge and a few veth pairs.  See
[util/README.md](util/README.md).


Origin and license
------------------

`mcd` started life as [querierd][], a stripped down `mrouted` for
Westermo's WeOS.  Version 1.0 marks the fork and rename, version 2.0
replaced the last of the `mrouted` code.  The project is maintained by
the [kernelkit][] team and licensed under the [ISC license][2].


[querierd]:  https://github.com/westermo/querierd
[kernelkit]: https://github.com/kernelkit
[1]: https://img.shields.io/badge/License-ISC-blue.svg
[2]: https://en.wikipedia.org/wiki/ISC_license
[3]: https://github.com/kernelkit/mcd/actions/workflows/build.yml/badge.svg
[4]: https://github.com/kernelkit/mcd/actions/workflows/build.yml/
[5]: https://scan.coverity.com/projects/30099/badge.svg
[6]: https://scan.coverity.com/projects/30099
