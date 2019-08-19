#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(webrtcneteq, [EL_RELEASE],, webrtcneteq-[EL_TIMESTAMP_CVSEXPORT])
AC_CONFIG_SRCDIR([src/webrtc_neteq_if.cpp])
AC_CONFIG_HEADERS([config.h])

CFLAGS="$CFLAGS $CONFIGURE_CFLAGS -D_GLIBCXX_USE_CXX11_ABI=0 -DWEBRTC_POSIX -DNETEQ_WIDEBAND -DNETEQ_32KHZ_WIDEBAND -DNETEQ_48KHZ_WIDEBAND -DNETEQ_G722_CODEC -DNETEQ_G711_CODEC -DNETEQ_OPUS_CODEC"
CXXFLAGS="$CXXFLAGS $CONFIGURE_CXXFLAGS"
LDFLAGS="$LDFLAGS $CONFIGURE_LDFLAGS"

AM_INIT_AUTOMAKE
AC_PROG_LIBTOOL
AC_PROG_CXX
AC_PROG_CC
AC_SUBST([DOLLAR_SIGN],[$])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_COMMANDS([build_opus.sh], [./build_opus.sh], [chmod +x build_opus.sh])
AC_CONFIG_COMMANDS([build_webrtc.sh], [./build_webrtc.sh], [chmod +x build_webrtc.sh])
AC_OUTPUT
