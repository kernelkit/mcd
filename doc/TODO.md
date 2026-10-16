Rough Plan for mcd
==================

General
-------

 - Look for better IP than 169 for each interface
 - Add basic bridge per-VLAN setup instead of setupd
 - Handle creating and removal of bridge interfaces where mcd is
   set to operate in raw VLAN mode


Later
-----

 - Add `vid NUM` filter to `show mdb`
 - Add support for optional view of reserved FRNT VLANs.  In the igmp app
   this was handled by a separate flag `-f` that activated filtering.  We
   currently always filter those VLANs.
 - Bridge configuration support, e.g. snooping on/off, query interval etc.


Future work
-----------

Findings from the October 2026 code review, noted but not acted on.

### MLD

 - Source lists in IGMPv3 and MLDv2 records are not tracked, RFC 5790
   lightweight semantics apply: a record with sources is a (*,G) join.

### Code structure

 - `struct ifi` is both the device (name, index, hardware address,
   addresses) and a querier instance (family, VLAN, querier state,
   groups, timers).  The per-family and per-VLAN clones each carry a
   copy of the device fields, link events walk the list to update
   every copy, and sock.c refcounts a socket to share it between
   them.  A per-device parent owning its querier entries would remove
   that bookkeeping, and let the membership list key on name rather
   than ifindex, which goes stale when a device is recreated.

### Static groups

 - Support raw VLAN mode.  The kernel cannot join on a specific VLAN of
   a bridge, so mcd would have to send its own tagged reports and
   answer queries for the group itself.
 - A `static-group` given before a second `vlan` keyword on the same
   `iface` line applies only to the first VLAN, since the clone starts
   with an empty static list.
