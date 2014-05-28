##################
#                #
#    Version     #
#                #
################

# Program version

define([SOFTHSM_VERSION_MAJOR], [1])
define([SOFTHSM_VERSION_MINOR], [3])
define([SOFTHSM_VERSION_FIX], [7])
define([PACKAGE_SUFFIX], [])

# Library version

# Code changed:                      SOFTHSM_VERSION_REVISION++
# Interface added/removed/changed:   SOFTHSM_VERSION_CURRENT++, SOFTHSM_VERSION_REVISION=0
# Interface added:                   SOFTHSM_VERSION_AGE++
# Interface removed:                 SOFTHSM_VERSION_AGE=0

define([SOFTHSM_VERSION_CURRENT], [1])
define([SOFTHSM_VERSION_AGE], [0])
define([SOFTHSM_VERSION_REVISION], [11])

##################
#                #
# Configure code #
#                #
##################

# Init 
AC_PREREQ(2.61)
AC_INIT([SoftHSM],[SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers
AC_PROG_CXX
AC_PROG_CC

ACX_PEDANTIC
ACX_STRICT

# Do not give warnings for long-long. So that we can build with newer SQLite3 
CPPFLAGS="${CPPFLAGS} -Wno-long-long"

# Configure arguments
AC_ARG_WITH(
        [loglevel],
        [AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
        [SOFTLOGLEVEL="$withval"],
        [SOFTLOGLEVEL=3]
)

ACX_64BIT

# Check for library include arguments
ACX_BOTAN
ACX_LIBSQLITE3
ACX_DLOPEN

YIELD_LIB=
dnl Solaris has sched_yield in librt, not in libpthread or libc.
AC_CHECK_LIB(rt, sched_yield, [YIELD_LIB=-lrt],
  [dnl Solaris 2.5.1, 2.6 has sched_yield in libposix4, not librt.
    AC_CHECK_LIB(posix4, sched_yield, [YIELD_LIB=-lposix4])])
AC_SUBST([YIELD_LIB])

AC_CHECK_FUNCS(getpassphrase)
AC_CHECK_HEADERS([sys/time.h dlfcn.h pthread.h syslog.h], [], [],
  [[#ifdef HAVE_DLFCN_H
  #include <dlfcn.h>
  #endif
  ]])

# Set full directory paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
default_softhsm_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/softhsm.conf"

# Install the library in a sub-directory
full_libdir="$full_libdir/softhsm"
libdir=$full_libdir

# Define some variables for the code
AC_DEFINE_UNQUOTED(
  [VERSION_MAJOR],
  [SOFTHSM_VERSION_MAJOR],
  [SoftHSM version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
  [VERSION_MINOR],
  [SOFTHSM_VERSION_MINOR],
  [SoftHSM version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
  [SOFTLOGLEVEL],
  [$SOFTLOGLEVEL],
  [The log level set by the user]
)
AC_DEFINE_UNQUOTED(
  [MAX_SESSION_COUNT],
  [256],
  [Maximum number of concurrent sessions]
)
AC_DEFINE_UNQUOTED(
  [MAX_PIN_LEN],
  [255],
  [Maximum PIN length]
)
AC_DEFINE_UNQUOTED(
  [MIN_PIN_LEN],
  [4],
  [Minimum PIN length]
)
AC_DEFINE_UNQUOTED(
  [DEFAULT_SOFTHSM_CONF],
  ["$default_softhsm_conf"],
  [The default location of softhsm.conf]
)

# Host specific configuration
AC_CANONICAL_HOST
case "${host}" in
*-*-winnt* | *-*-mingw* | *-*-cygwin*)
  AC_DEFINE_UNQUOTED(
    [DEFAULT_PKCS11_LIB],
    ["$full_libdir/libsofthsm.dll"],
    [The default PKCS#11 library]
  )
  ;;
*)
  AC_DEFINE_UNQUOTED(
    [DEFAULT_PKCS11_LIB],
    ["$full_libdir/libsofthsm.so"],
    [The default PKCS#11 library]
  )
  ;;
esac

# Generate the libtool script and install script 
AC_PROG_INSTALL
ifdef(
  [LT_INIT],
  [
    LT_INIT([win32-dll])
    LT_LANG([Windows Resource])
  ],
  [
    AC_LIBTOOL_WIN32_DLL
    AC_PROG_LIBTOOL
  ]
)

softhsmdbdir=${full_localstatedir}/lib/softhsm
AC_SUBST([softhsmdbdir])
AC_SUBST([default_softhsm_conf])

# Generate the make files
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/lib/Makefile
	src/bin/Makefile
	checks/Makefile
	softhsm.conf
	softhsm.conf.5
	src/bin/softhsm.1
])

AC_OUTPUT
