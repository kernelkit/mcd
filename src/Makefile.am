# For replacement functions in lib/
AUTOMAKE_OPTIONS = subdir-objects

# -D_GNU_SOURCE Use GNU extensions, where possible
# -D_BSD_SOURCE Use functions derived from 4.3 BSD Unix rather than POSIX.1
#               In GLIBC >= v2.20 this is replaced with -D_DEFAULT_SOURCE,
#               but to build on older GLIBC systems we now need both ...
AM_CPPFLAGS      = -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_GNU_SOURCE -I$(top_srcdir)/include
AM_CPPFLAGS     += -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\" -DPRESERVEDIR=\"@localstatedir@/lib\"
AM_CFLAGS        = -W -Wall -Wextra -Wno-unused -Wno-unused-parameter

sbin_PROGRAMS    = mcd mctl
mcd_SOURCES      = main.c cfparse.y config.c defs.h	\
		   iface.c iface.h netlink.c		\
		   igmp.c igmp.h			\
		   inet.c inet.h			\
		   ipc.c  ipc.h				\
		   log.c				\
		   bridge.c pev.c pev.h			\
		   pathnames.h queue.h
mcd_CPPFLAGS     = $(AM_CPPFLAGS)
mcd_LDADD        = $(LIBS) $(LIBOBJS)

mctl_SOURCES     = mctl.c queue.h
mctl_CPPFLAGS    = $(AM_CPPFLAGS)
mctl_LDADD       = $(LIBS) $(LIBOBJS)
