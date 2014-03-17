MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = no.token token.db K*.key* K*.private* *.pkcs8 

noinst_PROGRAMS = checks

AM_CPPFLAGS = 	-I$(srcdir)/../src/lib/cryptoki_compat \
		-DCHECKS_SOFTHSM_CONF='"$(srcdir)/softhsm.conf"'

EXTRA_DIST =	$(srcdir)/*.h \
		$(srcdir)/softhsm.conf

checks_LDADD = ../src/lib/libsofthsm.la -lstdc++
checks_LDFLAGS = -no-install -static -shared-libgcc

check-local:
	./checks -z

keyconv:
	sh $(srcdir)/keyconv.sh
