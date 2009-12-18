# $Id$

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

SUBDIRS = src checks

dist_man_MANS = softhsm.conf.5

EXTRA_DIST = $(srcdir)/m4/*.m4

install-data-hook:
	test -d ${sysconfdir} || \
		${INSTALL} -d ${DESTDIR}${sysconfdir}
	test -f ${sysconfdir}/softhsm.conf || \
		${INSTALL_DATA} ${top_builddir}/softhsm.conf ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/softhsm.conf ${DESTDIR}${sysconfdir}/softhsm.conf.sample
	test -d ${softhsmdbdir} || \
		${INSTALL} -d -m 700 ${DESTDIR}${softhsmdbdir}
