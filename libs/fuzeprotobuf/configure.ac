#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(fuzeprotobuf, [EL_RELEASE],, fuzeprotobuf-[EL_TIMESTAMP_CVSEXPORT])
AC_CONFIG_SRCDIR([src/ProtoBufIf.cpp])
AC_CONFIG_HEADERS([config.h])

CFLAGS="$CFLAGS $CONFIGURE_CFLAGS"
CXXFLAGS="$CXXFLAGS $CONFIGURE_CXXFLAGS"
LDFLAGS="$LDFLAGS $CONFIGURE_LDFLAGS"

AM_INIT_AUTOMAKE
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_CC
AC_SUBST([DOLLAR_SIGN],[$])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_COMMANDS([build_protos.sh], [./build_protos.sh], [chmod +x build_protos.sh])
AC_OUTPUT
