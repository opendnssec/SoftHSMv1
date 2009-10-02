/* $Id$ */

/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
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

#ifndef SOFTHSM_SOFTHSM_KEYCONV_H
#define SOFTHSM_SOFTHSM_KEYCONV_H 1

#include <botan/init.h>
#include <botan/base64.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/auto_rng.h>
using namespace Botan;

// Main functions

void usage();
void to_pkcs8(char *in_path, char *out_path, char *file_pin);
void to_bind(char *in_path, char *out_path);

// Support functions

void save_rsa_pkcs8(char *out_path, char *file_pin, BigInt bigN, BigInt bigE,
                    BigInt bigD, BigInt bigP, BigInt bigQ);
void save_dsa_pkcs8(char *out_path, char *file_pin, BigInt bigDP, BigInt bigDQ,
                    BigInt bigDG, BigInt bigDX);

// base64.c prototypes

#ifdef __cplusplus
extern "C" {
#endif
int b64_pton(const char *, u_char *, size_t);
int b64_ntop(const u_char *, size_t, char *, size_t);
#ifdef __cplusplus
}
#endif

// The BIND file version number.
#define FILE_MAJOR_VERSION      1
#define FILE_MINOR_VERSION      2

// Key algorithm number
#define DNS_KEYALG_RSAMD5       1
#define DNS_KEYALG_DSA          3
#define DNS_KEYALG_RSASHA1      5

// Maximum number of lines / line length
#define MAX_LINE 4096

// The text fields supported
static const char *file_tags[] = {
  "Private-key-format:",
  "Algorithm:",
  "Modulus:",
  "PublicExponent:",
  "PrivateExponent:",
  "Prime1:",
  "Prime2:",
  "Exponent1:",
  "Exponent2:",
  "Coefficient:",
  "Prime(p):",
  "Private_value(x):",
  "Public_value(y):",
  "Subprime(q):",
  "Base(g):",
  NULL
};

// The number of each text field.
// Must match the tags above.
enum FILE_TAGS {
  TAG_VERSION,
  TAG_ALGORITHM,
  TAG_MODULUS,
  TAG_PUBEXP,
  TAG_PRIVEXP,
  TAG_PRIME1,
  TAG_PRIME2,
  TAG_EXP1,
  TAG_EXP2,
  TAG_COEFF,
  TAG_PRIME,
  TAG_PRIVVAL,
  TAG_PUBVAL,
  TAG_SUBPRIME,
  TAG_BASE
};

#endif /* SOFTHSM_SOFTHSM_KEYCONV_H */