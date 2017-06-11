
bin_PROGRAMS = ratp-barebox-cli

ratp_barebox_cli_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/src/libratp-barebox \
	-I$(top_builddir)/src/libratp-barebox \
	$(NULL)

ratp_barebox_cli_LDADD = \
	$(top_builddir)/src/libratp-barebox/libratp-barebox.la \
	$(NULL)

ratp_barebox_cli_SOURCES = \
	ratp-barebox-cli.c \
	$(NULL)
