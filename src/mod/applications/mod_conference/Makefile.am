include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_conference

mod_LTLIBRARIES = mod_conference.la
mod_conference_la_SOURCES  = mod_conference.c conference_optimization.c conference_utils.c
mod_conference_la_CFLAGS   = $(AM_CFLAGS)
mod_conference_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_conference_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
