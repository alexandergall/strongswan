AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-snabb.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-snabb.la
endif

libstrongswan_kernel_snabb_la_SOURCES = \
	kernel_snabb_plugin.h kernel_snabb_plugin.c \
	kernel_snabb_ipsec.h kernel_snabb_ipsec.c

libstrongswan_kernel_snabb_la_LIBADD = $(DLLIB)

libstrongswan_kernel_snabb_la_LDFLAGS = -module -avoid-version
