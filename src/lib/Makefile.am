MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/cryptoki_compat \
				@BOTAN_INCLUDES@ \
				@SQLITE3_INCLUDES@

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp main.h \
				osmutex.cpp osmutex.h \
				MutexFactory.cpp MutexFactory.h \
				botan_compat.cpp botan_compat.h \
				file.cpp file.h \
				log.cpp log.h \
				attribute.cpp attribute.h \
				userhandling.cpp userhandling.h \
				tokenhandling.cpp tokenhandling.h \
				mechanisms.cpp mechanisms.h \
				SoftHSMInternal.cpp SoftHSMInternal.h \
				SoftSlot.cpp SoftSlot.h \
				SoftSession.cpp SoftSession.h \
				SoftFind.cpp SoftFind.h \
				SoftDatabase.cpp SoftDatabase.h \
				SoftKeyStore.cpp SoftKeyStore.h \
				util.h \
				cryptoki.h \
				cryptoki_compat/pkcs11.h
libsofthsm_la_LIBADD =		@BOTAN_LIBS@ @SQLITE3_LIBS@ @YIELD_LIB@
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				-avoid-version -module -no-undefined
