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

man_MANS = softhsm.conf.5

EXTRA_DIST = 	$(srcdir)/m4/*.m4 \
		$(srcdir)/LICENSE \
		$(srcdir)/README.md \
		$(srcdir)/README.MinGW \
		$(srcdir)/softhsm.conf.5.in

install-data-hook:
	test -d ${DESTDIR}${sysconfdir} || \
		${INSTALL} -d ${DESTDIR}${sysconfdir}
	test -f ${DESTDIR}${sysconfdir}/softhsm.conf || \
		${INSTALL_DATA} ${top_builddir}/softhsm.conf ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/softhsm.conf ${DESTDIR}${sysconfdir}/softhsm.conf.sample
	test -d ${DESTDIR}${softhsmdbdir} || \
		${INSTALL} -d -m 700 ${DESTDIR}${softhsmdbdir}
