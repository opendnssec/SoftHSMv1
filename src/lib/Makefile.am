# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/cryptoki_compat \
				@BOTAN_INCLUDES@ \
				@SQLITE3_INCLUDES@

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp \
				mutex.cpp \
				file.cpp \
				log.cpp \
				attribute.cpp \
				userhandling.cpp \
				tokenhandling.cpp \
				mechanisms.cpp \
				SoftHSMInternal.cpp \
				SoftSlot.cpp \
				SoftSession.cpp \
				SoftFind.cpp \
				SoftDatabase.cpp \
				SoftKeyStore.cpp
libsofthsm_la_LIBADD =		@BOTAN_LIBS@ @SQLITE3_LIBS@ @YIELD_LIB@
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				-avoid-version -module

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki_compat/*.h
