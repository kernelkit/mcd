AC_PREREQ([2.69])
AC_INIT([mcd], [2.4], [https://github.com/kernelkit/mcd/issues])
AC_CONFIG_AUX_DIR(.aux)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])

# Check for standard programs, headers, and functions
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_YACC

# Check for linux/netlink.h is only to be able to define LINUX below
AC_CHECK_HEADERS([fcntl.h ifaddrs.h sys/ioctl.h sys/time.h sys/socket.h linux/netlink.h termios.h])
AC_CHECK_HEADERS([net/if.h netinet/igmp.h netinet/in.h], [], [], [
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>])

# Check if some func is not in libc
AC_CHECK_LIB([util], [pidfile])

# Check for required functions in libc
AC_CHECK_FUNCS([atexit getifaddrs])

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([pidfile strlcpy strlcat strtonum tempfile utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

AC_MSG_CHECKING(for IPv6 multicast host support)
AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
                #ifdef HAVE_SYS_SOCKET_H
                # include <sys/socket.h>
                #endif
                #ifdef HAVE_NETINET_IN_H
                # include <netinet/in.h>
                #endif
        ]],[[
                struct ipv6_mreq mreq;
        ]])],[
        AC_DEFINE(HAVE_IPV6_MULTICAST_HOST, 1, [Define if your OS supports acting as an IPv6 multicast host])
        AC_MSG_RESULT(yes)],[
        AC_MSG_RESULT(no)])

AC_ARG_ENABLE(test,
        AS_HELP_STRING([--enable-test], [enable tests, requries unshare, tshark, etc.]),
        enable_test="$enableval", enable_test="no")

AC_ARG_WITH(group,
	AS_HELP_STRING([--with-group=NAME], [Group for /run/mcd.sock (mctl), default: root]),
	[group=$withval], [group=root])

# Create config.h from selected features and fallback defautls
AS_IF([test "x$with_group" != "xno"], [
	AS_IF([test "x$group" = "xyes"], [
		group=root])])
AC_DEFINE_UNQUOTED(DEFGROUP, "$group", [For /run/finit/socket])

AM_CONDITIONAL(BSD,         [test "x$ac_cv_header_net_if_dl_h"     = "xyes"])
AM_CONDITIONAL(LINUX,       [test "x$ac_cv_header_linux_netlink_h" = "xyes"])
AM_CONDITIONAL(ENABLE_TEST, [test "x$enable_test"                 != "xno"])

# Workaround for as-of-yet unreleased runstatedir support, planned for
# autoconf 2.70, which some major distros have backported.
AS_IF([test -z "$runstatedir"], runstatedir="$localstatedir/run")
AC_SUBST(runstatedir)

# Generate all files
AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Install prefix........: $prefix
  Configuration file....: `eval echo $sysconfdir`/mcd.conf
  PID and .sock files...: `eval echo $runstatedir`/
  C Compiler............: $CC $CFLAGS $CPPFLAGS $LDFLAGS $LIBS

Optional features:
  IPC group.............: $group
  Unit tests............: $enable_test

------------- Compiler version --------------
$($CC --version || true)
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
