EXTRA_DIST =
SUBDIRS = 
AUTOMAKE_OPTIONS = gnu
PREFIX=$(prefix)
NAME = fuzetransport 

AM_CFLAGS    = -std=c++0x $(new_AM_CFLAGS) -Wno-deprecated -I./src -I./src/core -I./src/polling -I./src/msg -I./include -I../Libevent/include -I../srtp/include -I../srtp/crypto/include
AM_CPPFLAGS  = $(AM_CFLAGS)
AM_LDFLAGS   = $(new_AM_LDFLAGS) -L.

DEFS = @DEFS@ -DSTD_SHARED_PTR -DNO_FUZECORE -DFREE_SWITCH

lib_LTLIBRARIES = libfuzetransport.la 
libfuzetransport_la_SOURCES = src/core/Log.cpp \
                         src/core/MutexLock.cpp \
                         src/core/ReadWriteLock.cpp \
                         src/core/Thread.cpp \
                         src/core/ConditionVariable.cpp \
                         src/core/Semaphore.cpp \
                         src/core/TimerService.cpp \
                         src/Transport.cpp \
                         src/TransportImpl.cpp \
                         src/TransportBaseImpl.cpp \
                         src/ConnectionImpl.cpp \
                         src/TcpListener.cpp \
                         src/TcpTransceiver.cpp \
                         src/UdpTransceiver.cpp \
                         src/DtlsTransceiver.cpp \
                         src/ResourceMgr.cpp \
                         src/Prober.cpp \
                         src/Address.cpp \
                         src/Stun.cpp \
                         src/Server.cpp \
                         src/ServerCore.cpp \
                         src/CoreState.cpp \
                         src/TcpCore.cpp \
                         src/TlsCore.cpp \
                         src/TcpTxrxState.cpp \
                         src/ProxyConnector.cpp \
                         src/DnsResolver.cpp \
                         src/MediaBridge.cpp \
                         src/msg/Message.cpp \
                         src/msg/Mapping.cpp \
                         src/msg/Data.cpp \
                         src/msg/HTTP.cpp \
                         src/polling/TransportEvent.cpp \
                         src/polling/TransportPoll.cpp 

libfuzetransport_la_LDFLAGS = -avoid-version -no-undefined $(AM_LDFLAGS)

library_includedir =  $(prefix)/include
library_include_HEADERS = include/Transport.h include/DnsResolver.h src/ConnectionImpl.h src/TcpTransceiver.h \
			src/polling/TransportEvent.h src/ResourceMgr.h src/Transceiver.h src/TransportImpl.h \
			src/TcpListener.h src/TransportBaseImpl.h src/UdpTransceiver.h src/DtlsTransceiver.h \
			src/core/Compat.h src/core/MutexLock.h src/polling/Queue.h \
			src/core/Thread.h src/core/Log.h src/core/NotCopyable.h \
			src/core/ConditionVariable.h include/Transport_c.h \
			include/Buffer.h src/CoreState.h src/Prober.h src/Resource.h \
			src/Server.h src/ServerCore.h src/TcpCore.h src/TcpCore.h \
			src/TcpTxrxState.h src/TlsCore.h src/MediaBridge.h src/core/Semaphore.h

