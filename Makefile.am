-include $(top_srcdir)/build/modmake.rulesam
AUTOMAKE_OPTIONS = foreign subdir-objects
MODNAME=mod_prometheus

LIBS := $(if $(switch_builddir),$(switch_builddir)/libfreeswitch.la,)

if HAVE_MICROHTTPD

mod_LTLIBRARIES = mod_prometheus.la
mod_prometheus_la_SOURCES  = mod_prometheus.c
mod_prometheus_la_CFLAGS   = $(AM_CFLAGS) $(FREESWITCH_CFLAGS) $(MICROHTTPD_CFLAGS)
mod_prometheus_la_LIBADD   = $(LIBS)
mod_prometheus_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(FREESWITCH_LIBS) $(MICROHTTPD_LIBS)

else
install: error
all: error
error:
    $(error You must install libmicrohttpd and libmicrohttpd-dev to build this module)
endif

install-data-local:
	test -d $(confdir)
	test -f $(confdir)/autoload_configs/prometheus.conf.xml || $(INSTALL) -m 644 conf/autoload_configs/prometheus.conf.xml $(confdir)/autoload_configs/prometheus.conf.xml
