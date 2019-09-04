EXTRA_DIST =
SUBDIRS = 
AUTOMAKE_OPTIONS = gnu
PREFIX=$(prefix)
NAME = fuzeprotobuf

AM_CFLAGS    = -std=c++0x $(new_AM_CFLAGS) -Wno-deprecated -I./include
AM_CPPFLAGS  = $(AM_CFLAGS)
AM_LDFLAGS   = $(new_AM_LDFLAGS) -L.

DEFS = @DEFS@ -DSTD_SHARED_PTR·

lib_LTLIBRARIES = libfuzeprotobuf.la
libfuzeprotobuf_la_SOURCES =	src/ProtoBufIf.cpp src/AudioQoS.pb.cc

libfuzeprotobuf_la_LDFLAGS = -avoid-version -no-undefined $(AM_LDFLAGS)

library_includedir =  $(prefix)/include
library_include_HEADERS = include/ProtoBufIf.h src/AudioQoS.pb.h

