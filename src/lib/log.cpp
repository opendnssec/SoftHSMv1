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
* Function for logging.
*
************************************************************/

#include "log.h"
#include "config.h"

#ifndef WIN32
#include <syslog.h>
#else
#include <windows.h>
#include <stdio.h>
#endif

void logError(const char *functionName, const char *text) {
#ifndef WIN32
  syslog(LOG_ERR, "SoftHSM: %s: %s", functionName, text);
#else
  HANDLE hEventLog = OpenEventLog(NULL, "SoftHSM");
  if(hEventLog) {
    char msg[1024];
    char* msgs[1];
    snprintf(msg, sizeof(msg), "%s: %s", functionName, text);
    msgs[0] = msg;
    ReportEvent(hEventLog, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, (const char **)msgs, NULL);
    CloseEventLog(hEventLog);
  }
#endif
}

void logWarning(const char *functionName, const char *text) {
#ifndef WIN32
  syslog(LOG_WARNING, "SoftHSM: %s: %s", functionName, text);
#else
  HANDLE hEventLog = OpenEventLog(NULL, "SoftHSM");
  if(hEventLog) {
    char msg[1024];
    char* msgs[1];
    snprintf(msg, sizeof(msg), "%s: %s", functionName, text);
    msgs[0] = msg;
    ReportEvent(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, NULL, 1, 0, (const char **)msgs, NULL);
    CloseEventLog(hEventLog);
  }
#endif
}

void logInfo(const char *functionName, const char *text) {
#ifndef WIN32
  syslog(LOG_INFO, "SoftHSM: %s: %s", functionName, text);
#else
  HANDLE hEventLog = OpenEventLog(NULL, "SoftHSM");
  if(hEventLog) {
    char msg[1024];
    char* msgs[1];
    snprintf(msg, sizeof(msg), "%s: %s", functionName, text);
    msgs[0] = msg;
    ReportEvent(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (const char **)msgs, NULL);
    CloseEventLog(hEventLog);
  }
#endif
}

void logDebug(const char *functionName, const char *text) {
#ifndef WIN32
  syslog(LOG_DEBUG, "SoftHSM: %s: %s", functionName, text);
#else
  logInfo(functionName, text);
#endif
}
