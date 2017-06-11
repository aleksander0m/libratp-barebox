
lib_LTLIBRARIES = libratp-barebox.la

libratp_barebox_la_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(LIBRATP_CFLAGS) \
	$(NULL)

libratp_barebox_la_SOURCES = \
	ratp-barebox.h \
	ratp-barebox.c \
	ratp-bb-common.h \
	$(NULL)

libratp_barebox_la_LDFLAGS = \
	$(LIBRATP_LIBS) \
	$(NULL)

include_HEADERS = \
	ratp-barebox.h \
	$(NULL)

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = ratp-barebox.pc

EXTRA_DIST = \
	ratp-barebox.h.in \
	$(NULL)
