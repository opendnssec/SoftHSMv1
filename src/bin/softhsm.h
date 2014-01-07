/*
 * Copyright (c) 2008-2011 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SOFTHSM_SOFTHSM_H
#define SOFTHSM_SOFTHSM_H 1

#include "cryptoki.h"
#include <sqlite3.h>

// Includes for the crypto library
#include <botan/pk_keys.h>
#include <botan/bigint.h>

typedef struct key_material_t {
  CK_ULONG sizeE;
  CK_ULONG sizeN;
  CK_ULONG sizeD;
  CK_ULONG sizeP;
  CK_ULONG sizeQ;
  CK_ULONG sizeDMP1;
  CK_ULONG sizeDMQ1;
  CK_ULONG sizeIQMP;
  CK_VOID_PTR bigE;
  CK_VOID_PTR bigN;
  CK_VOID_PTR bigD;
  CK_VOID_PTR bigP;
  CK_VOID_PTR bigQ;
  CK_VOID_PTR bigDMP1;
  CK_VOID_PTR bigDMQ1;
  CK_VOID_PTR bigIQMP;
  key_material_t() {
    sizeE = 0;
    sizeN = 0;
    sizeD = 0;
    sizeP = 0;
    sizeQ = 0;
    sizeDMP1 = 0;
    sizeDMQ1 = 0;
    sizeIQMP = 0;
    bigE = NULL_PTR;
    bigN = NULL_PTR;
    bigD = NULL_PTR;
    bigP = NULL_PTR;
    bigQ = NULL_PTR;
    bigDMP1 = NULL_PTR;
    bigDMQ1 = NULL_PTR;
    bigIQMP = NULL_PTR;
  }
} key_material_t;

// Main functions

void usage();
int initToken(char *slot, char *label, char *soPIN, char *userPIN);
int showSlots();
int importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectLabel, char *objectID, int forceExec);
int exportKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectID);
int optimize(char *slot, char *userPIN);
int trustObject(char *boolTrusted, char *slot, char *soPIN, char *type, char *label, char *objectID);

// Support functions

/// Hex
char* hexStrToBin(char *objectID, size_t idLength, size_t *newLen);
int hexdigit_to_int(char ch);

/// Key material
key_material_t* importKeyMat(char *filePath, char *filePIN);
void freeKeyMaterial(key_material_t *keyMaterial);

/// DB info
Botan::Private_Key* getPrivKey(char *dbPath, CK_OBJECT_HANDLE oHandle);
CK_KEY_TYPE getKeyType(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef);
CK_OBJECT_CLASS getObjectClass(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef);
Botan::BigInt getBigIntAttribute(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE_TYPE type);
int removeSessionObjs(char *dbPath);

/// Config
char* getDBPath(CK_SLOT_ID slotID);
CK_C_GetFunctionList loadLibrary(char *module);
static void *moduleHandle;
static CK_FUNCTION_LIST_PTR p11;

/// PKCS#11 support
CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, CK_OBJECT_CLASS oClass, char *label, char *objID, size_t objIDLen);

/// Key to file
CK_RV writeKeyToDisk(char *filePath, char *filePIN, Botan::Private_Key *privKey);

#endif /* SOFTHSM_SOFTHSM_H */
