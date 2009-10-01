# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../lib \
			-I$(srcdir)/../lib/cryptoki \
			@BOTAN_INCLUDES@ \
			@SQLITE3_INCLUDES@

bin_PROGRAMS =		softhsm softhsm-keyconv
softhsm_SOURCES =	softhsm.cpp softhsm.h
softhsm_LDADD =		../lib/libsofthsm.la -lstdc++

softhsm_keyconv_SOURCES =	softhsm-keyconv.cpp base64.c softhsm-keyconv.h
softhsm_keyconv_LDADD =		@BOTAN_LIBS@ -lstdc++

EXTRA_DIST =		$(srcdir)/*.h
