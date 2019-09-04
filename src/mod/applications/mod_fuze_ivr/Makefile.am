include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_fuze_ivr

mod_LTLIBRARIES = mod_fuze_ivr.la
mod_fuze_ivr_la_SOURCES  = mod_fuze_ivr.c ivr.c config.c menu.c utils.c fuzenode.c
mod_fuze_ivr_la_CFLAGS   = $(AM_CFLAGS)
mod_fuze_ivr_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_fuze_ivr_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
