include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_python

PYMOD=freeswitch
PYTHON_SITE_DIR=@PYTHON_SITE_DIR@

SWIGCFILE=../../../switch_swig.c
SWIGIFILE=../../../switch_swig.i

mod_LTLIBRARIES = mod_python.la
mod_python_la_SOURCES  = mod_python.c freeswitch_python.cpp mod_python_wrap.cpp
mod_python_la_CFLAGS   = $(AM_CFLAGS)
mod_python_la_CPPFLAGS = @PYTHON_CFLAGS@ -fpermissive -w -I$(switch_srcdir)/libs/libteletone/src/ 
mod_python_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_python_la_LDFLAGS  = -avoid-version -module -no-undefined -shared @PYTHON_LDFLAGS@

reswig: swigclean mod_python_wrap.cpp

swigclean: clean
	rm -f mod_python_wrap.* freeswitch.py

mod_python_wrap.cpp: mod_python_extra.c hack.diff 
	which swig 2>&1 >>/dev/null && swig -python -c++ -I../../../../src/include -oh mod_python_wrap.h -o mod_python_wrap.cpp mod_python.i
	which swig 2>&1 >>/dev/null && echo "#include \"mod_python_extra.c\"" >> mod_python_wrap.cpp
	which swig 2>&1 >>/dev/null && patch -s -p0 -i hack.diff

install-data-local:
	mkdir -m755 -p $(DESTDIR)$(PYTHON_SITE_DIR)
	cp -f freeswitch.py $(DESTDIR)$(PYTHON_SITE_DIR)

