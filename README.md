Bridge Querier Helper
=====================
[![License Badge][]][License] [![GitHub Status][]][GitHub] [![Coverity Status][]][Coverity Scan]

This daemon is a querier helper for the Linux bridge.  Currently IGMP
(IPv4) is supported, MLD (IPv6) querier support is planned.

The daemon comes with a little helper tool called `mctl` which
can be used to check the status of IGMP per interface, but also to
dump the bridge's MDB in a more human-friendly format.

Please note, for collecting status, `mcd` requires the tools `jq` and
iproute2 (`ip` and `bridge`) to be installed, their BusyBox equivalents
are not sufficient.


Usage
-----

For controlling `mcd` from another application, use the basic IPC
support that `mctl` employs:

    echo "help" |socat - UNIX-CONNECT:/run/mcd.sock

> See `mcd -h` for help, e.g. to customize the IPC path.


Configuration
-------------

By default `mcd` is passive on all interfaces.  Use the following
settings to enable and tweak the defaults.  There is no way to configure
different IGMP/MLD settings per interface at the moment, only protocol
version.

    # /etc/mcd.conf syntax
    global-query-interval [1-1024]            # default: 125 sec
    global-response-interval [1-1024]         # default: 10 sec
    global-last-member-interval [1-1024]      # default: 1
    robustness [2-10]                         # default: 2
    router-timeout [10-1024]                  # default: 255 sec
    
    iface IFNAME [enable] [vlan [1-4094]]     # default: disable
          [proxy-mode] [igmpv2 | igmpv3]
          [query-interval [1-1024]]

    include /path/to.d/*.conf

Description:

  * `global-query-interval`, `query-interval`: the interval between
    IGMP/MLD queries, when elected as querier for a LAN
  * `global-response-interval`: max response time to a query.  Can be
    used to control the burstiness of IGMP/MLD traffic
  * `global-last-member-interval`: time between group specific queries,
    the `robustness` setting controls the number of queries sent
  * `robustness`: controls the tolerance to loss of replies from end
    devices and the loss of elected queriers (above)
  * `router-timeout`: also known as *"other querier present interval"*,
    controls the timer used to detect when an elected querier stops
    sending queries.  When the timer expires `mcd` will initiate a
    query.  The default, when this is unset (commented out) is
    calculated based on: `robustness * query-interval +
    query-response-interval / 2`.  Setting this to any value overrides
    the RFC algorithm, which may be necessary in some scenarios, it is
    however strongly recommended to leave this setting commented out!
  * `include`: include a single file, or a glob expression matching
    files in a directory: `/etc/mc.d/*.conf`

All interfaces in the system are probed at start (and SIGHUP), to enable
mcd to act as a querier, use:

    iface IFNAME enable

This enables standard querier mode, using the interface's address as the
source IP in IGMP queries, `igmpv3` is default but mcd knows how to fall
back to IGMPv2 automatically if it detects legacy devices on the LAN.
To force IGMPv2 operation from start, set only the `igmpv2` flag.

If mcd should never participate in querier elections, only act as a LAN
backup querier, set the `proxy-mode` flag.  It ensures mcd always uses
the special source address 0.0.0.0 and is therefore guaranteed to never
win an election.

> **Note:** unless mcd has an IP address it will operate as if set to
> `proxy-mode`.  If the interface has no address, or does not yet exist
> when mcd starts up, mcd will adjust automatically since it listens to
> Linux NETLINK events.

mcd supports acting as a querier on VLAN filtering bridges that do not
have any "upper" interface.  In this raw mode of operating, mcd will
always be in `proxy-mode`.  To activate:

    iface br0 vlan 42 enable


[GitHub]:          https://github.com/kernelkit/mcd/actions/workflows/build.yml/
[GitHub Status]:   https://github.com/kernelkit/mcd/actions/workflows/build.yml/badge.svg
[License]:         https://en.wikipedia.org/wiki/ISC_license
[License Badge]:   https://img.shields.io/badge/License-ISC-blue.svg
[Coverity Scan]:   https://scan.coverity.com/projects/24475
[Coverity Status]: https://scan.coverity.com/projects/24475/badge.svg
