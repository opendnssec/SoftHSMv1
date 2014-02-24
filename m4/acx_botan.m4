AC_DEFUN([ACX_BOTAN],[
	AC_ARG_WITH(botan,
        	AC_HELP_STRING([--with-botan=PATH],[Specify prefix of path of Botan]),
		[
			BOTAN_PATH="$withval"
		],
		[
			BOTAN_PATH="/usr/local"
		])

	BOTAN_INCLUDES="-I$BOTAN_PATH/include/botan-1.10"
	BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan-1.10"
	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS
	CPPFLAGS="$CPPFLAGS $BOTAN_INCLUDES"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_MSG_CHECKING(for Botan >= 1.10.0)
	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <botan/init.h>
			#include <botan/version.h>],
			[using namespace Botan;
			#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,10,0)
			#error "Old API";
			#endif])],
		[BOTAN_v10="yes"],
		[BOTAN_v10="no"]
	)
	AC_LANG_POP([C++])
	AC_MSG_RESULT($BOTAN_v10)

	if test "$BOTAN_v10" = "no"
	then
		BOTAN_INCLUDES="-I$BOTAN_PATH/include"
		BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan"
		CPPFLAGS=$tmp_CPPFLAGS
		LIBS=$tmp_LIBS
		CPPFLAGS="$CPPFLAGS $BOTAN_INCLUDES"
		LIBS="$LIBS $BOTAN_LIBS"
	fi

	AC_MSG_CHECKING(what are the Botan includes)
	AC_MSG_RESULT($BOTAN_INCLUDES)

	AC_MSG_CHECKING(what are the Botan libs)
	AC_MSG_RESULT($BOTAN_LIBS)

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <botan/init.h>
			#include <botan/pipe.h>
			#include <botan/filters.h>
			#include <botan/hex.h>
			#include <botan/sha2_32.h>
			#include <botan/emsa3.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
			new EMSA3_Raw();])],
		[AC_MSG_RESULT([checking for Botan >= v1.8.0 ... yes])],
		[AC_MSG_RESULT([checking for Botan >= v1.8.0 ... no])
		 AC_MSG_ERROR([Missing the correct version of the Botan library])]
	)
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <botan/init.h>
			#include <botan/pipe.h>
			#include <botan/filters.h>
			#include <botan/hex.h>
			#include <botan/sha2_32.h>
			#include <botan/auto_rng.h>
			#include <botan/emsa3.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
			new EMSA3_Raw();
			AutoSeeded_RNG *rng = new AutoSeeded_RNG();
			rng->reseed();])],
		[AC_MSG_RESULT([checking for Botan reseed API fix ... no])],
		[AC_MSG_RESULT([checking for Botan reseed API fix ... yes])
		AC_DEFINE_UNQUOTED(
			[BOTAN_RESEED_FIX],
			[1],
			[Fixes an API problem within Botan]
		)]
	)
	if test "$BOTAN_v10" = "no"
	then
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([#include <botan/init.h>
				#include <botan/version.h>],
				[using namespace Botan;
				LibraryInitializer::initialize();
				#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,4)
				#error "Old API";
				#endif])],
			[AC_MSG_RESULT([checking for Botan 1.9.4 API change ... yes])],
			[AC_MSG_RESULT([checking for Botan 1.9.4 API change ... no])
			AC_DEFINE_UNQUOTED(
				[BOTAN_PRE_1_9_4_FIX],
				[1],
				[Fixes an API change within Botan]
			)]
		)
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([#include <botan/init.h>
				#include <botan/version.h>],
				[using namespace Botan;
				LibraryInitializer::initialize();
				#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,10)
				#error "Old API";
				#endif])],
			[AC_MSG_RESULT([checking for Botan 1.9.10 API change ... yes])],
			[AC_MSG_RESULT([checking for Botan 1.9.10 API change ... no])
			AC_DEFINE_UNQUOTED(
				[BOTAN_PRE_1_9_10_FIX],
				[1],
				[Fixes an API change within Botan]
			)]
		)
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([#include <botan/init.h>
				#include <botan/version.h>],
				[using namespace Botan;
				LibraryInitializer::initialize();
				#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,12)
				#error "Old API";
				#endif
				#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,11) && BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,9,0)
				#error "Old API";
				#endif])],
			[AC_MSG_RESULT([checking for Botan PK_Signer reuse ... yes])],
			[AC_MSG_RESULT([checking for Botan PK_Signer reuse ... no])
			AC_DEFINE_UNQUOTED(
				[BOTAN_NO_PK_SIGNER_REUSE],
				[1],
				[A bug in Botan prevents reuse of PK_Signer]
			)]
		)
	fi
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BOTAN_INCLUDES)
	AC_SUBST(BOTAN_LIBS)
])
