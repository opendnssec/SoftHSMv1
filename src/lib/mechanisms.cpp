/*
 * Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
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
* This file handles the info about the mechanisms
*
************************************************************/

#include "mechanisms.h"
#include "log.h"

// A list with the supported mechanisms
static CK_MECHANISM_TYPE supportedMechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,
  CKM_RSA_PKCS,
  CKM_RSA_X_509,
  CKM_MD5,
  CKM_RIPEMD160,
  CKM_SHA_1,
  CKM_SHA256,
  CKM_SHA384,
  CKM_SHA512,
  CKM_MD5_RSA_PKCS,
  CKM_RIPEMD160_RSA_PKCS,
  CKM_SHA1_RSA_PKCS,
  CKM_SHA256_RSA_PKCS,
  CKM_SHA384_RSA_PKCS,
  CKM_SHA512_RSA_PKCS,
  CKM_SHA1_RSA_PKCS_PSS,
  CKM_SHA256_RSA_PKCS_PSS,
  CKM_SHA384_RSA_PKCS_PSS,
  CKM_SHA512_RSA_PKCS_PSS
};

CK_RV getMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  CK_ULONG listSize = sizeof(supportedMechanisms) / sizeof(supportedMechanisms[0]);

  if(pMechanismList == NULL_PTR) {
    *pulCount = listSize;

    DEBUG_MSG("C_GetMechanismList", "OK, returning list length");
    return CKR_OK;
  }

  if(*pulCount < listSize) {
    *pulCount = listSize;

    DEBUG_MSG("C_GetMechanismList", "Buffer to small");
    return CKR_BUFFER_TOO_SMALL;
  }

  *pulCount = listSize;

  for(unsigned int i = 0; i < listSize; i++) {
    pMechanismList[i] = supportedMechanisms[i];
  }

  DEBUG_MSG("C_GetMechanismList", "OK, returning list");
  return CKR_OK;
}

CK_RV getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  CHECK_DEBUG_RETURN(pInfo == NULL_PTR, "C_GetMechanismInfo", "pInfo must not be a NULL_PTR",
                     CKR_ARGUMENTS_BAD);

  // Using fixed values because Botan got no interface to retrieve them.

  switch(type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_GENERATE_KEY_PAIR;
      break;
    case CKM_RSA_PKCS:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT;
      break;
    case CKM_RSA_X_509:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_SIGN | CKF_VERIFY;
      break;
    case CKM_MD5:
    case CKM_RIPEMD160:
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      pInfo->ulMinKeySize = 0;
      pInfo->ulMaxKeySize = 0;
      pInfo->flags = CKF_DIGEST;
      break;
    case CKM_MD5_RSA_PKCS:
    case CKM_RIPEMD160_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      pInfo->ulMinKeySize = 512;
      pInfo->ulMaxKeySize = 4096;
      pInfo->flags = CKF_SIGN | CKF_VERIFY;
      break;
    default:
      DEBUG_MSG("C_GetMechanismInfo", "The selected mechanism is not supported");
      return CKR_MECHANISM_INVALID;
      break;
  }

  DEBUG_MSG("C_GetMechanismInfo", "OK");
  return CKR_OK;
}
