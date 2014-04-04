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

/************************************************************
*
* SoftHSM
*
* This program is for creating and initializing tokens for
* the libsofthsm. libsofthsm implements parts of the PKCS#11
* interface defined by RSA Labratories, PKCS11 v2.20,
* called Cryptoki.
*
************************************************************/

#include <config.h>
#include "softhsm.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sched.h>

#ifdef HAVE_DLOPEN
#include <dlfcn.h>
#endif

#ifdef HAVE_LOADLIBRARY
#include <windows.h>
#endif

// Includes for the crypto library
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/if_algo.h>
#include <botan/init.h>
#include <botan/libstate.h>
#include <botan/numthry.h>

void usage() {
  printf("Support tool for libsofthsm\n");
  printf("Usage: softhsm [OPTIONS]\n");
  printf("Options:\n");
  printf("  --show-slots      Display all the available slots.\n");
  printf("  --init-token      Initialize the token at a given slot.\n");
  printf("                    Use with --slot, --label, --so-pin, and --pin.\n");
  printf("                    WARNING: Any content in token token will be erased.\n");
  printf("  --import <path>   Import a key pair from the given path.\n");
  printf("                    The file must be in PKCS#8-format.\n");
  printf("                    Use with --file-pin, --slot, --label, --id and --pin.\n");
  printf("  --export <path>   Export a key pair to the given path.\n");
  printf("                    The file will be written in PKCS#8-format.\n");
  printf("                    Cannot be used in combination with --module,\n");
  printf("                    since the keys are extracted from the SoftHSM database,\n");
  printf("                    thus not using PKCS#11.\n");
  printf("                    Use with --file-pin (will encrypt file), --slot, --id\n");
  printf("                    and --pin.\n");
  printf("  --optimize        Clean up leftovers (session objects in the database) from\n");
  printf("                    applications that haven't closed down properly.\n");
  printf("                    Cannot be used in combination with --module.\n");
  printf("                    Use with --slot and --pin.\n");
  printf("                    WARNING: Make sure that no application is currently\n");
  printf("                    using SoftHSM and session objects.\n");
  printf("  --trusted <bool>  Mark the object as trusted. true or false.\n");
  printf("                    Use with --slot, --so-pin, --type, and (--id or --label).\n");
  printf("  --file-pin <PIN>  Supply a PIN if the file is encrypted.\n");
  printf("  --force           Override some warnings.\n");
  printf("  -h                Shows this help screen.\n");
  printf("  --help            Shows this help screen.\n");
  printf("  --id <hex>        Defines the ID of the object. Hexadecimal characters.\n");
  printf("                    Use with --force if multiple key pairs may share\n");
  printf("                    the same ID.\n");
  printf("  --label <text>    Defines the label of the object or the token.\n");
  printf("  --module <path>   Use another PKCS#11 library than SoftHSM.\n");
  printf("  --pin <PIN>       The PIN for the normal user.\n");
  printf("  --slot <number>   The slot where the token is located.\n");
  printf("  --so-pin <PIN>    The PIN for the Security Officer (SO).\n");
  printf("  --type <text>     The type of object. CKO_PUBLIC_KEY or CKO_CERTIFICATE.\n");
  printf("  -v                Show version info.\n");
  printf("  --version         Show version info.\n");
  printf("\n");
  printf("\n");
  printf("You also need to have a configuration file to specify path to the\n");
  printf("token databases (default location: %s).\n", DEFAULT_SOFTHSM_CONF);
  printf("The path to the configuration file can be changed by the SOFTHSM_CONF\n");
  printf("environment variable, e.g.:\n");
  printf("    export SOFTHSM_CONF=/home/user/config.file\n");
  printf("\n");
  printf("An example of a configuration file:\n");
  printf("    0:/home/user/my.db\n");
  printf("    # Comments can be added\n");
  printf("    # Format:\n");
  printf("    # <slot number>:<path>\n");
  printf("    4:/home/user/token.database\n");
}

enum {
  OPT_SHOW_SLOTS = 0x100,
  OPT_INIT_TOKEN,
  OPT_IMPORT,
  OPT_EXPORT,
  OPT_OPTIMIZE,
  OPT_TRUSTED,
  OPT_SLOT,
  OPT_LABEL,
  OPT_MODULE,
  OPT_ID,
  OPT_SO_PIN,
  OPT_TYPE,
  OPT_PIN,
  OPT_FILE_PIN,
  OPT_FORCE,
  OPT_HELP,
  OPT_VERSION
};

static const struct option long_options[] = {
  { "show-slots",      0, NULL, OPT_SHOW_SLOTS },
  { "init-token",      0, NULL, OPT_INIT_TOKEN },
  { "import",          1, NULL, OPT_IMPORT },
  { "export",          1, NULL, OPT_EXPORT },
  { "optimize",        0, NULL, OPT_OPTIMIZE },
  { "trusted",         1, NULL, OPT_TRUSTED },
  { "slot",            1, NULL, OPT_SLOT },
  { "label",           1, NULL, OPT_LABEL },
  { "module",          1, NULL, OPT_MODULE },
  { "id",              1, NULL, OPT_ID },
  { "so-pin",          1, NULL, OPT_SO_PIN },
  { "type",            1, NULL, OPT_TYPE },
  { "pin",             1, NULL, OPT_PIN },
  { "file-pin",        1, NULL, OPT_FILE_PIN },
  { "force",           0, NULL, OPT_FORCE },
  { "help",            0, NULL, OPT_HELP },
  { "version",         0, NULL, OPT_VERSION },
  { NULL,              0, NULL, 0 }
};

#ifdef WIN32
#include <conio.h>
char *getpass(const char *prompt) {
  static char buf[MAX_PIN_LEN+1];
  size_t i;

  fputs(prompt, stderr);
  fflush(stderr);
  for(i = 0; i < sizeof(buf) - 1; i++) {
    buf[i] = _getch();
    if(buf[i] == '\r')
      break;
  }
  buf[i] = 0;
  fputs("\n", stderr);
  return buf;
}
#endif

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *inPath = NULL;
  char *outPath = NULL;
  char *soPIN = NULL;
  char *boolTrusted = NULL;
  char *type = NULL;
  char *userPIN = NULL;
  char *filePIN = NULL;
  char *label = NULL;
  char *module = NULL;
  char *objectID = NULL;
  char *slot = NULL;
  int forceExec = 0;

  int doInitToken = 0;
  int doShowSlots = 0;
  int doImport = 0;
  int doExport = 0;
  int doOptimize = 0;
  int doTrusted = 0;
  int action = 0;
  int status = 0;

  moduleHandle = NULL;
  p11 = NULL;
  bool was_initialized = false;

  while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_SHOW_SLOTS:
        doShowSlots = 1;
        action++;
        break;
      case OPT_INIT_TOKEN:
        doInitToken = 1;
        action++;
        break;
      case OPT_IMPORT:
        doImport = 1;
        action++;
        inPath = optarg;
        break;
      case OPT_EXPORT:
        doExport = 1;
        action++;
        outPath = optarg;
        break;
      case OPT_OPTIMIZE:
        doOptimize = 1;
        action++;
        break;
      case OPT_TRUSTED:
        doTrusted = 1;
        action++;
        boolTrusted = optarg;
        break;
      case OPT_SLOT:
        slot = optarg;
        break;
      case OPT_LABEL:
        label = optarg;
        break;
      case OPT_MODULE:
        module = optarg;
        break;
      case OPT_ID:
        objectID = optarg;
        break;
      case OPT_SO_PIN:
        soPIN = optarg;
        break;
      case OPT_TYPE:
        type = optarg;
        break;
      case OPT_PIN:
        userPIN = optarg;
        break;
      case OPT_FILE_PIN:
        filePIN = optarg;
        break;
      case OPT_FORCE:
        forceExec = 1;
        break;
      case OPT_VERSION:
      case 'v':
        printf("%s\n", PACKAGE_VERSION);
        return 0;
        break;
      case OPT_HELP:
      case 'h':
        usage();
        return 0;
        break;
      default:
        usage();
        return 1;
        break;
    }
  }

  // No action given, display the usage.
  if(action != 1) {
    fprintf(stderr, "Error: Must perform one action.\n\n");
    usage();
    return 1;
  } else {
    CK_C_GetFunctionList pGetFunctionList = loadLibrary(module);
    if(pGetFunctionList == NULL) {
      fprintf(stderr, "Error: Could not load the library.\n");
      return 1;
    }
    (*pGetFunctionList)(&p11);

    CK_RV rv = p11->C_Initialize(NULL_PTR);
    if(rv != CKR_OK) {
      fprintf(stderr, "Error: Could not initialize libsofthsm. Probably missing the configuration file.\n");
      return 1;
    }
  }

  // The PKCS#11 library might be using Botan
  // Check if it has already initialized Botan
#ifdef BOTAN_PRE_1_9_10_FIX
  Botan::Library_State* state = Botan::swap_global_state(0);
  Botan::swap_global_state(state);

  if(state) {
#else
  if(Botan::Global_State_Management::global_state_exists()) {
#endif
    was_initialized = true;
  }

  if(was_initialized == false) {
    Botan::LibraryInitializer::initialize("thread_safe=true");
  }

  // We should create the token.
  if(doInitToken) {
    status = initToken(slot, label, soPIN, userPIN);
  }

  // Show all available slots
  if(doShowSlots) {
    status = showSlots();
  }

  // Import a key pair from the given path
  if(doImport) {
    status = importKeyPair(inPath, filePIN, slot, userPIN, label, objectID, forceExec);
  }

  // Export a key pair to the given path
  if(doExport) {
    if(module) {
      fprintf(stderr, "Error: Cannot perform export in combination with the module option.\n");
      status = 1;
    } else {
      status = exportKeyPair(outPath, filePIN, slot, userPIN, objectID);
    }
  }

  // Remove session objects
  if(doOptimize) {
    if(module) {
      fprintf(stderr, "Error: Cannot perform optimization in combination with the module option.\n");
      status = 1;
    } else {
      status = optimize(slot, userPIN);
    }
  }

  // Set CKA_TRUSTED
  if(doTrusted) {
    status = trustObject(boolTrusted, slot, soPIN, type, label, objectID);
  }

  if(was_initialized == false) {
    Botan::LibraryInitializer::deinitialize();
  }

  if(action) {
    p11->C_Finalize(NULL_PTR);
    if(moduleHandle) {
#if defined(HAVE_LOADLIBRARY)
      FreeLibrary((HMODULE)moduleHandle);
#elif defined(HAVE_DLOPEN)
      dlclose(moduleHandle);
#endif
    }
  }

  return status;
}

// Load the PKCS#11 library
CK_C_GetFunctionList loadLibrary(char *module) {
  CK_C_GetFunctionList pGetFunctionList = NULL;

#if defined(HAVE_LOADLIBRARY)
  // Load PKCS #11 library
  HMODULE pDynLib = NULL;
  if(module) {
    pDynLib = LoadLibrary(module);
  } else {
    pDynLib = LoadLibrary(DEFAULT_PKCS11_LIB);
  }

  if(pDynLib == NULL) {
    // Failed to load the PKCS #11 library
    return NULL;
  }

  // Retrieve the entry point for C_GetFunctionList
  pGetFunctionList = (CK_C_GetFunctionList) GetProcAddress(pDynLib, "C_GetFunctionList");

  // Store the handle so we can close it later
  moduleHandle = pDynLib;

#elif defined(HAVE_DLOPEN)
  // Load PKCS #11 library
  void* pDynLib;
  if(module) {
    pDynLib = dlopen(module, RTLD_NOW | RTLD_LOCAL);
  } else {
    pDynLib = dlopen(DEFAULT_PKCS11_LIB, RTLD_NOW | RTLD_LOCAL);
  }

  if(pDynLib == NULL) {
    // Failed to load the PKCS #11 library
    return NULL;
  }

  // Retrieve the entry point for C_GetFunctionList
  pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");

  // Store the handle so we can dlclose it later
  moduleHandle = pDynLib;

#else
  return NULL;
#endif

  return pGetFunctionList;
}

// Creates a SoftHSM token at the given location.

int initToken(char *slot, char *label, char *soPIN, char *userPIN) {
  // Keep a copy of the PINs because getpass/getpassphrase will overwrite the previous PIN.
  char so_pin_copy[MAX_PIN_LEN+1];
  char user_pin_copy[MAX_PIN_LEN+1];

  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return 1;
  }

  if(label == NULL) {
    fprintf(stderr, "Error: A label for the token must be supplied. Use --label <text>\n");
    return 1;
  }

  if(strlen(label) > 32) {
    fprintf(stderr, "Error: The token label must not have a length greater than 32 chars.\n");
    return 1;
  }

  if(soPIN == NULL) {
    printf("The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
  }

  int soLength = strlen(soPIN);
  while(soLength < MIN_PIN_LEN || soLength > MAX_PIN_LEN) {
    printf("Wrong size! The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
    soLength = strlen(soPIN);
  }
  strcpy(so_pin_copy, soPIN);

  if(userPIN == NULL) {
    printf("The user PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Enter user PIN: ");
    #else
      userPIN = getpass("Enter user PIN: ");
    #endif
  }

  int userLength = strlen(userPIN);
  while(userLength < MIN_PIN_LEN || userLength > MAX_PIN_LEN) {
    printf("Wrong size! The user PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      userPIN = getpassphrase("Enter user PIN: ");
    #else
      userPIN = getpass("Enter user PIN: ");
    #endif
    userLength = strlen(userPIN);
  }
  strcpy(user_pin_copy, userPIN);

  // Load the variables
  CK_SLOT_ID slotID = atoi(slot);
  CK_UTF8CHAR paddedLabel[32];
  memset(paddedLabel, ' ', sizeof(paddedLabel));
  memcpy(paddedLabel, label, strlen(label));

  CK_RV rv = p11->C_InitToken(slotID, (CK_UTF8CHAR_PTR)so_pin_copy, soLength, paddedLabel);

  switch(rv) {
    case CKR_OK:
      break;
    case CKR_SLOT_ID_INVALID:
      fprintf(stderr, "Error: The given slot does not exist.\n");
      return 1;
      break;
    case CKR_PIN_INCORRECT:
      fprintf(stderr, "Error: The given SO PIN does not match the one in the token.\n");
      return 1;
      break;
    case CKR_TOKEN_NOT_PRESENT:
      fprintf(stderr, "Error: The token is not present.\n");
      fprintf(stderr, "Error: Probably missing write permissions, please check the path and file given in the configuration.\n");
      return 1;
      break;
    default:
      fprintf(stderr, "Error: The library could not initialize the token.\n");
      return 1;
      break;
  }

  CK_SESSION_HANDLE hSession;
  rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not open a session with the library.\n");
    return 1;
  }

  rv = p11->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin_copy, soLength);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not log in on the token.\n");
    return 1;
  }

  rv = p11->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)user_pin_copy, userLength);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not initialize the user PIN.\n");
    return 1;
  }

  printf("The token has been initialized.\n");

  return 0;
}

int showSlots() {
  CK_ULONG ulSlotCount;
  CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not get the number of slots.\n");
    return 1;
  }

  CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
  rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    fprintf(stderr, "Error: Could not get the slot list.\n");
    return 1;
  }

  printf("Available slots:\n");

  for(unsigned int i = 0; i < ulSlotCount; i++) {
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;

    rv = p11->C_GetSlotInfo(pSlotList[i], &slotInfo);
    if(rv != CKR_OK) {
      fprintf(stderr, "Error: Could not get the slot info.\n");
      free(pSlotList);
      return 1;
    }

    printf("Slot %-2lu\n", pSlotList[i]);
    printf("           Token present: ");
    if((slotInfo.flags & CKF_TOKEN_PRESENT) == 0) {
      printf("no\n");
    } else {
      printf("yes\n");

      rv = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
      if(rv != CKR_OK) {
        fprintf(stderr, "Error: Could not get the token info.\n");
        return 1;
      }

      printf("           Token initialized: ");
      if((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0) {
        printf("no\n");
      } else {
        printf("yes\n");
      }

      printf("           User PIN initialized: ");
      if((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == 0) {
        printf("no\n");
      } else {
        printf("yes\n");
      }

      if((tokenInfo.flags & CKF_TOKEN_INITIALIZED) != 0) {
        printf("           Token label: %.*s\n", 32, tokenInfo.label);
      }
    }
  }

  free(pSlotList);

  return 0;
}

// Import a key pair from given path

int importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *label, char *objectID, int forceExec) {
  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return 1;
  }

  if(label == NULL) {
    fprintf(stderr, "Error: A label for the object must be supplied. Use --label <text>\n");
    return 1;
  }

  if(userPIN == NULL) {
    fprintf(stderr, "Error: An user PIN must be supplied. Use --pin <PIN>\n");
    return 1;
  }

  if(objectID == NULL) {
    fprintf(stderr, "Error: An ID for the object must be supplied. Use --id <hex>\n");
    return 1;
  }
  size_t objIDLen = 0;
  char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
  if(objID == NULL) {
    fprintf(stderr, "Please edit --id <hex> to correct error.\n");
    return 1;
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    free(objID);
    return 1;
  }

  rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    free(objID);
    return 1;
  }

  CK_OBJECT_HANDLE oHandle = searchObject(hSession, CKO_PRIVATE_KEY, NULL, objID, objIDLen);
  if(oHandle != CK_INVALID_HANDLE && forceExec == 0) {
    free(objID);
    fprintf(stderr, "Error: The ID is already assigned to another object. Use --force to override this message.\n");
    return 1;
  }

  key_material_t *keyMat = importKeyMat(filePath, filePIN);
  if(keyMat == NULL) {
    free(objID);
    return 1;
  }

  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
  CK_ATTRIBUTE pubTemplate[] = {
    { CKA_CLASS,            &pubClass,    sizeof(pubClass) },
    { CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
    { CKA_LABEL,            label,        strlen(label) },
    { CKA_ID,               objID,        objIDLen },
    { CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
    { CKA_VERIFY,           &ckTrue,      sizeof(ckTrue) },
    { CKA_ENCRYPT,          &ckFalse,     sizeof(ckFalse) },
    { CKA_WRAP,             &ckFalse,     sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
    { CKA_MODULUS,          keyMat->bigN, keyMat->sizeN }
  };
  CK_ATTRIBUTE privTemplate[] = {
    { CKA_CLASS,            &privClass,   sizeof(privClass) },
    { CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
    { CKA_LABEL,            label,        strlen(label) },
    { CKA_ID,               objID,        objIDLen },
    { CKA_SIGN,             &ckTrue,      sizeof(ckTrue) },
    { CKA_DECRYPT,          &ckFalse,     sizeof(ckFalse) },
    { CKA_UNWRAP,           &ckFalse,     sizeof(ckFalse) },
    { CKA_SENSITIVE,        &ckTrue,      sizeof(ckTrue) },
    { CKA_TOKEN,            &ckTrue,      sizeof(ckTrue) },
    { CKA_PRIVATE,          &ckTrue,      sizeof(ckTrue) },
    { CKA_EXTRACTABLE,      &ckFalse,     sizeof(ckFalse) },
    { CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
    { CKA_MODULUS,          keyMat->bigN, keyMat->sizeN },
    { CKA_PRIVATE_EXPONENT, keyMat->bigD, keyMat->sizeD },
    { CKA_PRIME_1,          keyMat->bigP, keyMat->sizeP },
    { CKA_PRIME_2,          keyMat->bigQ, keyMat->sizeQ },
    { CKA_EXPONENT_1,       keyMat->bigDMP1, keyMat->sizeDMP1 },
    { CKA_EXPONENT_2,       keyMat->bigDMQ1, keyMat->sizeDMQ1 },
    { CKA_COEFFICIENT,      keyMat->bigIQMP, keyMat->sizeIQMP }
  };

  CK_OBJECT_HANDLE hKey1, hKey2;
  rv = p11->C_CreateObject(hSession, privTemplate, 19, &hKey1);
  if(rv != CKR_OK) {
    freeKeyMaterial(keyMat);
    free(objID);
    fprintf(stderr, "Error: Could not save the private key in the token.\n");
    return 1;
  }

  rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);

  freeKeyMaterial(keyMat);
  free(objID);

  if(rv != CKR_OK) {
    p11->C_DestroyObject(hSession, hKey1);
    fprintf(stderr, "Error: Could not save the public key in the token.\n");
    return 1;
  }

  printf("The key pair has been imported to the token in slot %lu.\n", slotID);

  return 0;
}

int exportKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectID) {
  if(filePIN != NULL) {
    int filePinLen = strlen(filePIN);
    if(filePinLen < MIN_PIN_LEN || filePinLen > MAX_PIN_LEN) {
      fprintf(stderr, "Error: The file PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
      return 1;
    }
  }

  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return 1;
  }

  if(userPIN == NULL) {
    fprintf(stderr, "Error: An user PIN must be supplied. Use --pin <PIN>\n");
    return 1;
  }

  if(objectID == NULL) {
    fprintf(stderr, "Error: An ID for the object must be supplied. Use --id <hex>\n");
    return 1;
  }
  size_t objIDLen = 0;
  char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
  if(objID == NULL) {
    fprintf(stderr, "Please edit --id <hex> to correct error.\n");
    return 1;
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    free(objID);
    return 1;
  }

  rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    free(objID);
    return 1;
  }

  // Find the object handle
  CK_OBJECT_HANDLE oHandle = searchObject(hSession, CKO_PRIVATE_KEY, NULL, objID, objIDLen);
  free(objID);
  if(oHandle == CK_INVALID_HANDLE) {
    fprintf(stderr, "Error: Could not find the private key with ID = %s\n", objectID);
    return 1;
  }

  // Get the path to the token database
  char *dbPath = getDBPath(slotID);
  if(dbPath == NULL) {
    return 1;
  }

  // Extract the key directly from the database
  Botan::Private_Key *privKey = getPrivKey(dbPath, oHandle);
  free(dbPath);
  if(privKey == NULL) {
    return 1;
  }

  // Write the key to disk
  rv = writeKeyToDisk(filePath, filePIN, privKey);
  if(rv == CKR_OK) {
    printf("The key pair has been written to %s\n", filePath);
  }

  delete privKey;

  return 0;
}

int optimize(char *slot, char *userPIN) {
  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return 1;
  }

  if(userPIN == NULL) {
    fprintf(stderr, "Error: An user PIN must be supplied. Use --pin <PIN>\n");
    return 1;
  }

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    return 1;
  }

  rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    return 1;
  }

  // Get the path to the token database
  char *dbPath = getDBPath(slotID);
  if(dbPath == NULL) {
    return 1;
  }

  if(!removeSessionObjs(dbPath)) {
    printf("Removed all session objects.\n");
  }

  free(dbPath);

  return 0;
}

int trustObject(char *boolTrusted, char *slot, char *soPIN, char *type, char *label, char *objectID) {
  char so_pin_copy[MAX_PIN_LEN+1];
  CK_BBOOL trusted;
  CK_OBJECT_CLASS oClass;

  if(boolTrusted == NULL) {
    fprintf(stderr, "Error: A boolean value must be supplied. Use --trusted <bool>\n");
    return 1;
  }
  if(strncasecmp(boolTrusted, "true", 4) == 0) {
    trusted = CK_TRUE;
  } else if(strncasecmp(boolTrusted, "false", 5) == 0) {
    trusted = CK_FALSE;
  } else {
    fprintf(stderr, "Error: Please use true or false as an input for --trusted <bool>\n");
    return 1;
  }

  if(slot == NULL) {
    fprintf(stderr, "Error: A slot number must be supplied. Use --slot <number>\n");
    return 1;
  }

  if(objectID == NULL && label == NULL) {
    fprintf(stderr, "Error: An ID or label for the object must be supplied. Use --id <hex> or --label <text>\n");
    return 1;
  }
  size_t objIDLen = 0;
  char *objID = NULL;
  if(objectID != NULL) {
    objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
    if(objID == NULL) {
      fprintf(stderr, "Please edit --id <hex> to correct error.\n");
      return 1;
    }
  }

  if(type == NULL) {
    fprintf(stderr, "Error: An object type must must be supplied. Use --type <text>\n");
    if(objID) free(objID);
    return 1;
  }
  if(strncasecmp(type, "CKO_CERTIFICATE", 15) == 0) {
    oClass = CKO_CERTIFICATE;
  } else if(strncasecmp(type, "CKO_PUBLIC_KEY", 14) == 0) {
    oClass = CKO_PUBLIC_KEY;
  } else {
    fprintf(stderr, "Error: Please use CKO_CERTIFICATE or CKO_PUBLIC_KEY as an input for --type <text>\n");
    if(objID) free(objID);
    return 1;
  }

  if(soPIN == NULL) {
    printf("The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
  }

  int soLength = strlen(soPIN);
  while(soLength < MIN_PIN_LEN || soLength > MAX_PIN_LEN) {
    printf("Wrong size! The SO PIN must have a length between %i and %i characters.\n", MIN_PIN_LEN, MAX_PIN_LEN);
    #ifdef HAVE_GETPASSPHRASE
      soPIN = getpassphrase("Enter SO PIN: ");
    #else
      soPIN = getpass("Enter SO PIN: ");
    #endif
    soLength = strlen(soPIN);
  }
  strcpy(so_pin_copy, soPIN);

  CK_SLOT_ID slotID = atoi(slot);
  CK_SESSION_HANDLE hSession;
  CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  if(rv != CKR_OK) {
    if(rv == CKR_SLOT_ID_INVALID) {
      fprintf(stderr, "Error: The given slot does not exist.\n");
    } else {
      fprintf(stderr, "Error: Could not open a session on the given slot.\n");
    }
    if(objID) free(objID);
    return 1;
  }

  rv = p11->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin_copy, soLength);
  if(rv != CKR_OK) {
    if(rv == CKR_PIN_INCORRECT) {
      fprintf(stderr, "Error: The given user PIN does not match the one in the token.\n");
    } else {
      fprintf(stderr, "Error: Could not log in on the token.\n");
    }
    if(objID) free(objID);
    return 1;
  }

  // Find object
  CK_OBJECT_HANDLE oHandle = searchObject(hSession, oClass, label, objID, objIDLen);
  if(objID) free(objID);
  if(oHandle == CK_INVALID_HANDLE) {
    fprintf(stderr, "Error: Could not find a matching object. The SO can only see public objects.\n");
    return 1;
  }

  // Set value
  CK_ATTRIBUTE objTemplate[] = {
    { CKA_TRUSTED, &trusted, sizeof(trusted) }
  };
  rv = p11->C_SetAttributeValue(hSession, oHandle, objTemplate, 1);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not modify CKA_TRUSTED. rv = 0x%08X\n", (unsigned int)rv);
    return 1;
  }

  printf("The CKA_TRUSTED has been modified.\n");

  return 0;
}

int removeSessionObjs(char *dbPath) {
  sqlite3 *db = NULL;
  const char select_str[] = "SELECT objectID FROM Attributes WHERE type = ? AND value = ?;";
  const char delete_str[] = "DELETE FROM Objects WHERE objectID = ?;";
  sqlite3_stmt *select_sql = NULL;
  sqlite3_stmt *delete_sql = NULL;
  CK_BBOOL ckFalse = CK_FALSE;
  int retVal = 0;

  if(sqlite3_open(dbPath, &db) != 0) {
    fprintf(stderr, "ERROR: Could not connect to database.\n");
    return 1;
  }

  if(sqlite3_prepare_v2(db, select_str, -1, &select_sql, NULL) != 0) {
    fprintf(stderr, "ERROR: Could not prepare a SQL statement.\n");
    sqlite3_close(db);
    return 1;
  }

  if(sqlite3_prepare_v2(db, delete_str, -1, &delete_sql, NULL) != 0) {
    fprintf(stderr, "ERROR: Could not prepare a SQL statement.\n");
    sqlite3_finalize(select_sql);
    sqlite3_close(db);
    return 1;
  }

  sqlite3_bind_int(select_sql, 1, CKA_TOKEN);
  sqlite3_bind_blob(select_sql, 2, &ckFalse, sizeof(ckFalse), SQLITE_TRANSIENT);

  while((retVal = sqlite3_step(select_sql)) == SQLITE_BUSY || retVal == SQLITE_ROW) {
    if(retVal == SQLITE_ROW) {
      sqlite3_bind_int(delete_sql, 1, sqlite3_column_int(select_sql, 0));
      while(sqlite3_step(delete_sql) == SQLITE_BUSY) {
        sched_yield();
      }
      sqlite3_reset(delete_sql);
    } else {
      sched_yield();
    }
  }

  sqlite3_finalize(delete_sql);
  sqlite3_finalize(select_sql);
  sqlite3_close(db);

  return 0;
}

// Convert a char array of hexadecimal characters into a binary representation

char* hexStrToBin(char *objectID, size_t idLength, size_t *newLen) {
  char *bytes = NULL;

  if(idLength < 2 || idLength % 2 != 0) {
    fprintf(stderr, "Error: Invalid length on hex string.\n");
    return NULL;
  }

  for(size_t i = 0; i < idLength; i++) {
    if(hexdigit_to_int(objectID[i]) == -1) {
      fprintf(stderr, "Error: Invalid character in hex string.\n");
      return NULL;
    }
  }

  *newLen = idLength / 2;
  bytes = (char *)malloc(*newLen);
  if(bytes == NULL) {
    fprintf(stderr, "Error: Could not allocate memory.\n");
    return NULL;
  }

  for(size_t i = 0; i < *newLen; i++) {
    bytes[i] = hexdigit_to_int(objectID[2*i]) * 16 +
               hexdigit_to_int(objectID[2*i+1]);
  }
  return bytes;
}

// Return the integer value of a hexadecimal character

int hexdigit_to_int(char ch) {
  switch (ch) {
    case '0':
      return 0;
    case '1':
      return 1;
    case '2':
      return 2;
    case '3':
      return 3;
    case '4':
      return 4;
    case '5':
      return 5;
    case '6':
      return 6;
    case '7':
      return 7;
    case '8':
      return 8;
    case '9':
      return 9;
    case 'a':
    case 'A':
      return 10;
    case 'b':
    case 'B':
      return 11;
    case 'c':
    case 'C':
      return 12;
    case 'd':
    case 'D':
      return 13;
    case 'e':
    case 'E':
      return 14;
    case 'f':
    case 'F':
      return 15;
    default:
      return -1;
  }
}

// Import key material from file

key_material_t* importKeyMat(char *filePath, char *filePIN) {
  if(filePath == NULL) {
    return NULL;
  }

  Botan::AutoSeeded_RNG *rng = new Botan::AutoSeeded_RNG();
  Botan::Private_Key *privKey = NULL;

  try {
    if(filePIN == NULL) {
      privKey = Botan::PKCS8::load_key(filePath, *rng);
    } else {
      privKey = Botan::PKCS8::load_key(filePath, *rng, filePIN);
    }
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Perhaps wrong path to file, wrong file format, or wrong PIN to file (--file-pin <PIN>).\n");
    delete rng;
    return NULL;
  }
  delete rng;

  if(privKey->algo_name().compare("RSA") != 0) {
    fprintf(stderr, "Error: %s is not a supported algorithm. Only RSA is supported.\n", privKey->algo_name().c_str());
    delete privKey;
    return NULL;
  }

  Botan::IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<Botan::IF_Scheme_PrivateKey*>(privKey);
  Botan::BigInt d1 = ifKeyPriv->get_d() % (ifKeyPriv->get_p() - 1);
  Botan::BigInt d2 = ifKeyPriv->get_d() % (ifKeyPriv->get_q() - 1);
  Botan::BigInt c = inverse_mod(ifKeyPriv->get_q(), ifKeyPriv->get_p());
  key_material_t *keyMat = (key_material_t *)malloc(sizeof(key_material_t));
  keyMat->sizeE = ifKeyPriv->get_e().bytes();
  keyMat->sizeN = ifKeyPriv->get_n().bytes();
  keyMat->sizeD = ifKeyPriv->get_d().bytes();
  keyMat->sizeP = ifKeyPriv->get_p().bytes();
  keyMat->sizeQ = ifKeyPriv->get_q().bytes();
  keyMat->sizeDMP1 = d1.bytes();
  keyMat->sizeDMQ1 = d2.bytes();
  keyMat->sizeIQMP = c.bytes();
  keyMat->bigE = (CK_VOID_PTR)malloc(keyMat->sizeE);
  keyMat->bigN = (CK_VOID_PTR)malloc(keyMat->sizeN);
  keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
  keyMat->bigP = (CK_VOID_PTR)malloc(keyMat->sizeP);
  keyMat->bigQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
  keyMat->bigDMP1 = (CK_VOID_PTR)malloc(keyMat->sizeDMP1);
  keyMat->bigDMQ1 = (CK_VOID_PTR)malloc(keyMat->sizeDMQ1);
  keyMat->bigIQMP = (CK_VOID_PTR)malloc(keyMat->sizeIQMP);
  ifKeyPriv->get_e().binary_encode((Botan::byte *)keyMat->bigE);
  ifKeyPriv->get_n().binary_encode((Botan::byte *)keyMat->bigN);
  ifKeyPriv->get_d().binary_encode((Botan::byte *)keyMat->bigD);
  ifKeyPriv->get_p().binary_encode((Botan::byte *)keyMat->bigP);
  ifKeyPriv->get_q().binary_encode((Botan::byte *)keyMat->bigQ);
  d1.binary_encode((Botan::byte *)keyMat->bigDMP1);
  d2.binary_encode((Botan::byte *)keyMat->bigDMQ1);
  c.binary_encode((Botan::byte *)keyMat->bigIQMP);
  delete privKey;

  return keyMat;
}

// Free the memory for the key material container

void freeKeyMaterial(key_material_t *keyMaterial) {
  if(keyMaterial != NULL) {
    if(keyMaterial->bigE != NULL) {
      free(keyMaterial->bigE);
    }
    if(keyMaterial->bigN != NULL) {
      free(keyMaterial->bigN);
    }
    if(keyMaterial->bigD != NULL) {
      free(keyMaterial->bigD);
    }
    if(keyMaterial->bigP != NULL) {
      free(keyMaterial->bigP);
    }
    if(keyMaterial->bigQ != NULL) {
      free(keyMaterial->bigQ);
    }
    if(keyMaterial->bigDMP1 != NULL) {
      free(keyMaterial->bigDMP1);
    }
    if(keyMaterial->bigDMQ1 != NULL) {
      free(keyMaterial->bigDMQ1);
    }
    if(keyMaterial->bigIQMP != NULL) {
      free(keyMaterial->bigIQMP);
    }

    free(keyMaterial);
  }
}

// Search for an object

CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, CK_OBJECT_CLASS oClass, char *label, char *objID, size_t objIDLen) {
  if(objID == NULL && label == NULL ) {
    return CK_INVALID_HANDLE;
  }
  CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
  CK_ULONG objectCount = 0;
  CK_ULONG labelLen = 0;
  if(label) labelLen = strlen(label);

  CK_ATTRIBUTE objTemplateID[] = {
    { CKA_CLASS, &oClass, sizeof(oClass) },
    { CKA_ID,    objID,   objIDLen }
  };
  CK_ATTRIBUTE objTemplateLabel[] = {
    { CKA_CLASS, &oClass, sizeof(oClass) },
    { CKA_LABEL, label,   labelLen }
  };

  CK_RV rv;
  if(objID != NULL) {
    rv = p11->C_FindObjectsInit(hSession, objTemplateID, 2);
  } else {
    rv = p11->C_FindObjectsInit(hSession, objTemplateLabel, 2);
  }
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not prepare the object search.\n");
    return CK_INVALID_HANDLE;
  }

  rv = p11->C_FindObjects(hSession, &hObject, 1, &objectCount);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not get the search results.\n");
    return CK_INVALID_HANDLE;
  }

  rv = p11->C_FindObjectsFinal(hSession);
  if(rv != CKR_OK) {
    fprintf(stderr, "Error: Could not finalize the search.\n");
    return CK_INVALID_HANDLE;
  }

  if(objectCount == 0) {
    return CK_INVALID_HANDLE;
  }

  return hObject;
}

// Write the key pair to disk

CK_RV writeKeyToDisk(char *filePath, char *filePIN, Botan::Private_Key *privKey) {
  if(filePath == NULL || privKey == NULL) {
    return CKR_GENERAL_ERROR;
  }

  std::ofstream privFile(filePath);

  if(!privFile) {
    fprintf(stderr, "Error: Could not open file for for output.\n");
    return CKR_GENERAL_ERROR;
  }

  Botan::AutoSeeded_RNG *rng = new Botan::AutoSeeded_RNG();

  try {
    if(filePIN == NULL) {
      privFile << Botan::PKCS8::PEM_encode(*privKey);
    } else {
      privFile << Botan::PKCS8::PEM_encode(*privKey, *rng, filePIN);
    }
  }
  catch(std::exception& e) {
    delete rng;
    privFile.close();
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not write to file.\n");
    return CKR_GENERAL_ERROR;
  }

  delete rng;
  privFile.close();

  return CKR_OK;
}

// Get the path to the database for this slot

char* getDBPath(CK_SLOT_ID slotID) {
  FILE *fp;

  const char *confPath = getenv("SOFTHSM_CONF");

  if(confPath == NULL) {
    confPath = DEFAULT_SOFTHSM_CONF;
  }

  fp = fopen(confPath,"r");

  if(fp == NULL) {
    fprintf(stderr, "Error: Could not open the config file: %s", confPath);
    return NULL;
  }

  char fileBuf[1024];

  // Format in config file
  //
  // slotID:dbPath
  // # Line is ignored

  char *realPath = NULL;
  while(fgets(fileBuf, sizeof(fileBuf), fp) != NULL) {
    // End the string at the first comment or newline
    fileBuf[strcspn(fileBuf, "#\n\r")] = '\0';

    // Get the first part of the line
    char *slotidstr = strtok(fileBuf, ":");

    // Check that we have a digit in the first position, so it can be parsed.
    if(slotidstr == NULL || !isdigit((int)*slotidstr)) {
      continue;
    }

    CK_SLOT_ID currentSlot = atoi(slotidstr);
    if(currentSlot == slotID) {
      // Get the second part of the line
      char *dbPath = strtok(NULL, ":");
      if(dbPath == NULL) {
        break;
      }

      int startPos = 0;
      int endPos = strlen(dbPath);

      // Find the first position without a space
      while(isspace((int)*(dbPath + startPos)) && startPos < endPos) {
        startPos++;
      }
      // Find the last position without a space
      while(isspace((int)*(dbPath + endPos)) && startPos < endPos) {
        endPos--;
      }

      // We must have a valid string
      int length = endPos - startPos;
      if(length <= 0) {
        break;
      }

      // Create the real DB path
      realPath = (char *)malloc(length + 1);
      if(realPath != NULL) {
        realPath[length] = '\0';
        memcpy(realPath, dbPath + startPos, length);
      }
      break;
    }
  }

  fclose(fp);

  if(realPath == NULL) {
    fprintf(stderr, "Error: Could not get the path to the token database.\n");
  }

  return realPath;
}

// Returns a big int of a given attribute.

Botan::BigInt getBigIntAttribute(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE_TYPE type) {
  Botan::BigInt retVal = Botan::BigInt(0);

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, type);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR) {
      retVal = Botan::BigInt((Botan::byte *)pValue, (Botan::u32bit)length);
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Return the class of the object

CK_OBJECT_CLASS getObjectClass(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef) {
  CK_OBJECT_CLASS retVal = CKO_VENDOR_DEFINED;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, CKA_CLASS);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR && length == sizeof(CK_OBJECT_CLASS)) {
      retVal = *(CK_OBJECT_CLASS *)pValue;
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Return the key type of the object

CK_KEY_TYPE getKeyType(sqlite3_stmt *select_an_attribute_sql, CK_OBJECT_HANDLE objectRef) {
  CK_KEY_TYPE retVal = CKK_VENDOR_DEFINED;

  sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
  sqlite3_bind_int(select_an_attribute_sql, 2, CKA_KEY_TYPE);

  // Get attribute
  if(sqlite3_step(select_an_attribute_sql) == SQLITE_ROW) {
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
    CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

    if(pValue != NULL_PTR && length == sizeof(CK_KEY_TYPE)) {
      retVal = *(CK_KEY_TYPE *)pValue;
    }
  }

  sqlite3_reset(select_an_attribute_sql);

  return retVal;
}

// Get the private key from database

Botan::Private_Key* getPrivKey(char *dbPath, CK_OBJECT_HANDLE oHandle) {
  sqlite3 *db = NULL;
  const char select_str[] = "SELECT value,length FROM Attributes WHERE objectID = ? AND type = ?;";
  sqlite3_stmt *select_sql = NULL;
  Botan::Private_Key *privKey = NULL;

  if(sqlite3_open(dbPath, &db) == 0 && sqlite3_prepare_v2(db, select_str, -1, &select_sql, NULL) == 0) {
    if(getObjectClass(select_sql, oHandle) == CKO_PRIVATE_KEY && getKeyType(select_sql, oHandle) == CKK_RSA) {
      Botan::BigInt bigN = getBigIntAttribute(select_sql, oHandle, CKA_MODULUS);
      Botan::BigInt bigE = getBigIntAttribute(select_sql, oHandle, CKA_PUBLIC_EXPONENT);
      Botan::BigInt bigD = getBigIntAttribute(select_sql, oHandle, CKA_PRIVATE_EXPONENT);
      Botan::BigInt bigP = getBigIntAttribute(select_sql, oHandle, CKA_PRIME_1);
      Botan::BigInt bigQ = getBigIntAttribute(select_sql, oHandle, CKA_PRIME_2);

      Botan::AutoSeeded_RNG *rng = new Botan::AutoSeeded_RNG();
      
      try {
        privKey = new Botan::RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
      }
      catch(...) {
        fprintf(stderr, "Error: Could not extract the private key material from database.\n");
      }

      delete rng;
    } else {
      fprintf(stderr, "Error: Object class or key type not supported.\n");
    }
  } else {
    fprintf(stderr, "Error: Database handling error.\n");
  }

  if(select_sql != NULL) {
    sqlite3_finalize(select_sql);
  }

  if(db != NULL) {
    sqlite3_close(db);
  }

  return privKey;
}
