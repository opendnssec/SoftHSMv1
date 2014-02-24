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
* This class handles the internal state.
* Mainly session and object handling.
*
************************************************************/

#ifndef SOFTHSM_SOFTHSMINTERNAL_H
#define SOFTHSM_SOFTHSMINTERNAL_H 1

#include "cryptoki.h"
#include "SoftFind.h"
#include "SoftDatabase.h"
#include "SoftSession.h"
#include "SoftSlot.h"
#include "MutexFactory.h"

class SoftFind;
class SoftDatabase;
class SoftSession;
class SoftSlot;

class SoftHSMInternal {
  public:
    SoftHSMInternal();
    ~SoftHSMInternal();

    // Session Handling
    int getSessionCount();
    CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, 
      CK_SESSION_HANDLE_PTR phSession);
    CK_RV closeSession(CK_SESSION_HANDLE hSession);
    CK_RV closeAllSessions(CK_SLOT_ID slotID);
    CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    SoftSession* getSession(CK_SESSION_HANDLE hSession);

    // User handling
    CK_RV login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, 
      CK_ULONG ulPinLen);
    CK_RV logout(CK_SESSION_HANDLE hSession);

    // Token handling
    CK_RV initToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_RV initPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV setPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

    // Object handling
    CK_RV createObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV destroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, 
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV setAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, 
      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, 
      CK_ULONG ulCount);

    // Slots
    // No need for mutex. Created on init, then we only read from it.
    SoftSlot *slots;

  private:
    int openSessions;
    SoftSession *sessions[MAX_SESSION_COUNT];
    Mutex* sessionsMutex;

    char appID[32];
};

#endif /* SOFTHSM_SOFTHSMINTERNAL_H */
