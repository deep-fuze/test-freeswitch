EXTRA_DIST =
SUBDIRS = 
AUTOMAKE_OPTIONS = gnu subdir-objects
PREFIX=$(prefix)
NAME = webrtcneteq

WEBRTC_INC_DIR=./SDK/webrtc
WEBRTC_LIB_DIR = .
WEBRTC_LIBS = $(WEBRTC_LIB_DIR)/libwebrtccore.a

# -std=c++11 or -std=gnu++11
AM_CFLAGS    =  -std=c++0x $(new_AM_CFLAGS) -I./src -I../spandsp/src -I../opus-1.3-rc/include -I$(WEBRTC_INC_DIR) -I$(WEBRTC_INC_DIR)/src -I$(WEBRTC_INC_DIR)/include
AM_CPPFLAGS  = $(AM_CFLAGS)
AM_LDFLAGS   = $(new_AM_LDFLAGS) -L. -L$(WEBRTC_LIB_DIR)

DEFS = @DEFS@ -D_GLIBCXX_USE_CXX11_ABI=0 -DWEBRTC_POSIX -DNETEQ_WIDEBAND -DNETEQ_32KHZ_WIDEBAND -DNETEQ_48KHZ_WIDEBAND -DNETEQ_G722_CODEC -DNETEQ_G711_CODEC -DNETEQ_OPUS_CODEC

lib_LTLIBRARIES = libwebrtcneteq.la 
libwebrtcneteq_la_SOURCES = src/webrtc_neteq_if.cpp
libwebrtcneteq_la_LDFLAGS = 	-avoid-version -no-undefined $(AM_LDFLAGS) $(WEBRTC_LIBS)

library_includedir =  $(prefix)/include
library_include_HEADERS = src/interface/webrtc_neteq_if.h
