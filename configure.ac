dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.68])

dnl The libadn version number
m4_define([ratp_barebox_major_version], [0])
m4_define([ratp_barebox_minor_version], [0])
m4_define([ratp_barebox_micro_version], [5])
m4_define([ratp_barebox_version],
          [ratp_barebox_major_version.ratp_barebox_minor_version.ratp_barebox_micro_version])

AC_INIT([libratp-barebox], [ratp_barebox_version], [aleksander@aleksander.es])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 foreign no-define no-dist-gzip dist-xz tar-ustar -Wno-portability])
AM_MAINTAINER_MODE([enable])

dnl Support silent build rules. Disable
dnl by either passing --disable-silent-rules to configure or passing V=1
dnl to make
AM_SILENT_RULES([yes])

dnl Required programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

dnl Initialize libtool
LT_PREREQ([2.2])
LT_INIT

dnl Specific warnings to always use
LIBRATP_BAREBOX_COMPILER_WARNINGS

dnl Version stuff
RATP_BAREBOX_MAJOR_VERSION=ratp_barebox_major_version
RATP_BAREBOX_MINOR_VERSION=ratp_barebox_minor_version
RATP_BAREBOX_MICRO_VERSION=ratp_barebox_micro_version
RATP_BAREBOX_VERSION=ratp_barebox_version
AC_SUBST(RATP_BAREBOX_MAJOR_VERSION)
AC_SUBST(RATP_BAREBOX_MINOR_VERSION)
AC_SUBST(RATP_BAREBOX_MICRO_VERSION)
AC_SUBST(RATP_BAREBOX_VERSION)

dnl Dependencies
LIBRATP_VERSION=0.0.2

dnl libratp (mandatory)
PKG_CHECK_MODULES([LIBRATP], [ratp >= $LIBRATP_VERSION])

dnl Documentation
GTK_DOC_CHECK(1.0)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/libratp-barebox/Makefile
                 src/libratp-barebox/ratp-barebox.pc
                 src/libratp-barebox/ratp-barebox.h
                 src/ratp-barebox-cli/Makefile
                 doc/Makefile
                 doc/reference/Makefile
                 doc/reference/version.xml])
AC_OUTPUT

echo "
    libratp-barebox $VERSION
    ==============================================

    compiler:         ${CC}
    cflags:           ${CFLAGS}
    ldflags:          ${LDFLAGS}
    maintainer mode:  ${USE_MAINTAINER_MODE}
    documentation:    ${enable_gtk_doc}
"
