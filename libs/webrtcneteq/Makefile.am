EXTRA_DIST =
SUBDIRS = 
AUTOMAKE_OPTIONS = gnu subdir-objects
PREFIX=$(prefix)
NAME = webrtcneteq

WEBRTC_LIB_DIR = lib/x64/Release
WEBRTC_LIBS = 
#-lwebrtc
#-lboringssl -lfield_trial_default -lprotobuf_full -lprotoc_lib -lwebrtc -lcpu_features_linux -lmetrics_default -lprotobuf_lite -lsystem_wrappers

AM_CFLAGS    = -std=c++0x $(new_AM_CFLAGS) -I./src -I../spandsp/src -I../opus-1.2.1/include -I./src/include
AM_CPPFLAGS  = $(AM_CFLAGS)
AM_LDFLAGS   = $(new_AM_LDFLAGS) -L. -L$(WEBRTC_LIB_DIR)

DEFS = @DEFS@ -DWEBRTC_POSIX -DNETEQ_WIDEBAND -DNETEQ_32KHZ_WIDEBAND -DNETEQ_48KHZ_WIDEBAND -DNETEQ_G722_CODEC -DNETEQ_G711_CODEC -DNETEQ_OPUS_CODEC

lib_LTLIBRARIES = libwebrtcneteq.la 
libwebrtcneteq_la_SOURCES = src/webrtc_neteq_if.cpp
libwebrtcneteq_la_LDFLAGS = 	-avoid-version -no-undefined $(AM_LDFLAGS) $(WEBRTC_LIBS)

library_includedir =  $(prefix)/include
library_include_HEADERS = src/interface/webrtc_neteq_if.h
