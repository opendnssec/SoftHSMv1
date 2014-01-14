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
* Functions for validating attributes.
*
************************************************************/

#include "attribute.h"
#include "log.h"

// Standard includes
#include <stdlib.h>
#include <stdio.h>

// Includes for the crypto library
#include <botan/if_algo.h>
#include <botan/rsa.h>

CK_RV valAttributeCertificate(CK_STATE state, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  int foundType = 0;
  int foundSubject = 0;
  int foundValue = 0;
  CK_BBOOL trusted;

  // Evaluate the template
  for(CK_ULONG i = 0; i < ulCount; i++) {
    if(pTemplate[i].pValue == NULL_PTR && pTemplate[i].ulValueLen > 0) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    switch(pTemplate[i].type) {
      case CKA_CLASS:
        // Check for the correct size
        if(pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          CK_OBJECT_CLASS oClass = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
          if(oClass != CKO_CERTIFICATE) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_CERTIFICATE_TYPE:
        // Check for the correct size
        if(pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE)) {
          CK_OBJECT_CLASS oType = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
          if(oType != CKC_X_509) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        foundType = 1;
        break;
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
        // Check for the correct size
        if(pTemplate[i].ulValueLen != sizeof(CK_BBOOL)) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_TRUSTED:
        // Check for the correct size
        if(pTemplate[i].ulValueLen != sizeof(CK_BBOOL)) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        // CKA_TRUSTED can only be set to true by SO
        trusted = *(CK_BBOOL*)pTemplate[i].pValue;
        if(state != CKS_RW_SO_FUNCTIONS && trusted != CK_FALSE) {
          return CKR_ATTRIBUTE_READ_ONLY;
        }
        break;
      case CKA_LABEL:
      case CKA_CHECK_VALUE:
      case CKA_ID:
      case CKA_ISSUER:
      case CKA_SERIAL_NUMBER:
      case CKA_URL:
      case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
      case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        // Variable length, no need to check
        break;
      case CKA_SUBJECT:
        // Variable length, no need to check
        foundSubject = 1;
        break;
      case CKA_VALUE:
        // Variable length, no need to check
        foundValue = 1;
        break;
      case CKA_CERTIFICATE_CATEGORY:
      case CKA_JAVA_MIDP_SECURITY_DOMAIN:
        // Check for the correct size
        if(pTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
          CK_ULONG value = *(CK_ULONG*)pTemplate[i].pValue;
          if(value > 3) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pTemplate[i].ulValueLen != sizeof(CK_DATE) &&
           pTemplate[i].ulValueLen != 0) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      default:
        // Invalid attribute
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if(!foundType || !foundSubject || !foundValue) {
    return CKR_TEMPLATE_INCOMPLETE;
  } 

  return CKR_OK;
}

CK_RV valAttributePubRSA(CK_STATE state, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  Botan::BigInt bigN = Botan::BigInt(0);
  Botan::BigInt bigE = Botan::BigInt(0);
  CK_BBOOL trusted;

  // Evaluate the template
  for(CK_ULONG i = 0; i < ulCount; i++) {
    if(pTemplate[i].pValue == NULL_PTR && pTemplate[i].ulValueLen > 0) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    switch(pTemplate[i].type) {
      case CKA_CLASS:
        if(pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          CK_OBJECT_CLASS oClass = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
          if(oClass != CKO_PUBLIC_KEY) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_KEY_TYPE:
        if(pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
          CK_KEY_TYPE keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
          if(keyType != CKK_RSA) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_DERIVE:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
        // Check for the correct size
        if(pTemplate[i].ulValueLen != sizeof(CK_BBOOL)) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_LABEL:
      case CKA_ID:
      case CKA_SUBJECT:
        // Variable length, no need to check
        break;
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pTemplate[i].ulValueLen != sizeof(CK_DATE) &&
           pTemplate[i].ulValueLen != 0) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_LOCAL:
      case CKA_KEY_GEN_MECHANISM:
      case CKA_MODULUS_BITS:
        // Must not be specified when object is created with C_CreateObject
        return CKR_ATTRIBUTE_VALUE_INVALID;
      case CKA_TRUSTED:
        // Check for the correct size
        if(pTemplate[i].ulValueLen != sizeof(CK_BBOOL)) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        // CKA_TRUSTED can only be set to true by SO
        trusted = *(CK_BBOOL*)pTemplate[i].pValue;
        if(state != CKS_RW_SO_FUNCTIONS && trusted != CK_FALSE) {
          return CKR_ATTRIBUTE_READ_ONLY;
        }
        break;
      case CKA_PUBLIC_EXPONENT:
        bigE = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_MODULUS:
        bigN = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      default:
        // Invalid attribute
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if(bigN.is_zero() || bigE.is_zero()) {
    return CKR_TEMPLATE_INCOMPLETE;
  }

  Botan::Public_Key *tmpKey = NULL_PTR;
  try {
    tmpKey = new Botan::RSA_PublicKey(bigN, bigE);
  }
  catch(std::exception& e) {
    char errorMsg[1024];
    snprintf(errorMsg, sizeof(errorMsg), "Could not re-create the public key: %s", e.what());
    ERROR_MSG("valAttributePubRSA", errorMsg);

    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  if(tmpKey != NULL_PTR) {
    delete tmpKey;
  }

  return CKR_OK;
}

CK_RV valAttributePrivRSA(CK_STATE state, Botan::RandomNumberGenerator *rng, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  // Unused variable, but saved if we ever need to do checks on the state
  (void) state;

  Botan::BigInt bigN = Botan::BigInt(0);
  Botan::BigInt bigE = Botan::BigInt(0);
  Botan::BigInt bigD = Botan::BigInt(0);
  Botan::BigInt bigP = Botan::BigInt(0);
  Botan::BigInt bigQ = Botan::BigInt(0);

  // Evaluate the template
  for(CK_ULONG i = 0; i < ulCount; i++) {
    if(pTemplate[i].pValue == NULL_PTR && pTemplate[i].ulValueLen > 0) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    switch(pTemplate[i].type) {
      case CKA_CLASS:
        if(pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          CK_OBJECT_CLASS oClass = *(CK_OBJECT_CLASS*)pTemplate[i].pValue;
          if(oClass != CKO_PRIVATE_KEY) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_KEY_TYPE:
        if(pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
          CK_KEY_TYPE keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
          if(keyType != CKK_RSA) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
          }
        } else {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_DERIVE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP:
      case CKA_SENSITIVE:
      case CKA_EXTRACTABLE:
      case CKA_WRAP_WITH_TRUSTED:
      case CKA_ALWAYS_AUTHENTICATE:
        // Check for the correct size
        if(pTemplate[i].ulValueLen != sizeof(CK_BBOOL)) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_LABEL:
      case CKA_ID:
      case CKA_SUBJECT:
        // Variable length, no need to check
        break;
      case CKA_START_DATE:
      case CKA_END_DATE:
        if(pTemplate[i].ulValueLen != sizeof(CK_DATE) &&
           pTemplate[i].ulValueLen != 0) {
          return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        break;
      case CKA_LOCAL:
      case CKA_KEY_GEN_MECHANISM:
      case CKA_ALWAYS_SENSITIVE:
      case CKA_NEVER_EXTRACTABLE:
        // Must not be specified when object is created with C_CreateObject
        return CKR_ATTRIBUTE_VALUE_INVALID;
      case CKA_PUBLIC_EXPONENT:
        bigE = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_MODULUS:
        bigN = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_PRIVATE_EXPONENT:
        bigD = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_PRIME_1:
        bigP = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_PRIME_2:
        bigQ = Botan::BigInt((Botan::byte *)pTemplate[i].pValue, (Botan::u32bit)pTemplate[i].ulValueLen);
        break;
      case CKA_EXPONENT_1:
      case CKA_EXPONENT_2:
      case CKA_COEFFICIENT:
        // We accept it, but do not use it.
        break;
      default:
        // Invalid attribute
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if(bigN.is_zero () || bigE.is_zero() || bigD.is_zero() || bigP.is_zero() || bigQ.is_zero()) {
    return CKR_TEMPLATE_INCOMPLETE;
  }

  Botan::Public_Key *tmpKey = NULL_PTR;
  try {
    tmpKey = new Botan::RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
  }
  catch(std::exception& e) {
    char errorMsg[1024];
    snprintf(errorMsg, sizeof(errorMsg), "Could not re-create the private key: %s", e.what());
    ERROR_MSG("valAttributePrivRSA", errorMsg);

    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  if(tmpKey != NULL_PTR) {
    delete tmpKey;
  }

  return CKR_OK;
}
