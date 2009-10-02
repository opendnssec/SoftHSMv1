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

/************************************************************
*
* softhsm-keyconv
*
* This program is for converting from/to BIND .private-key
* format to/from PKCS#8 key file format. So that keys can be
* imported/exported from/to BIND to/from SoftHSM.
*
* Some of the design/code is from keyconv.c written by 
* Hakan Olsson and Jakob Schlyter in 2000 and 2001.
*
************************************************************/

#include <config.h>
#include "softhsm-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <stdint.h>

void usage() {
  printf("Converting between BIND .private-key format and PKCS#8 key file format.\n");
  printf("Usage: softhsm-keyconv [OPTIONS]\n");
  printf("Options:\n");
  printf("  --topkcs8     Convert from BIND .private-key format to PKCS#8.\n");
  printf("                    Use with --in, --out, and --pin.\n");
  printf("  --tobind      Convert from PKCS#8 to BIND .private-key format.\n");
  printf("                    Use with --in and --out.\n");
  printf("  -h            Shows this help screen.\n");
  printf("  --help        Shows this help screen.\n");
  printf("  --in <path>   The path to the input file.\n");
  printf("  --out <path>  The path to the output file.\n");
  printf("  --pin <PIN>   To encrypt/decrypt PKCS#8 file. Optional.\n");
}

// Give a number to each option
enum {
  OPT_TOPKCS8 = 0x100,
  OPT_TOBIND,
  OPT_HELP,
  OPT_IN,
  OPT_OUT,
  OPT_PIN
};

// Define the options
static const struct option long_options[] = {
  { "topkcs8",    0, NULL, OPT_TOPKCS8 },
  { "tobind",     0, NULL, OPT_TOBIND },
  { "help",       0, NULL, OPT_HELP },
  { "in",         1, NULL, OPT_IN },
  { "out",        1, NULL, OPT_OUT },
  { "pin",        1, NULL, OPT_PIN },
  { NULL,         0, NULL, 0 }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *in_path = NULL;
  char *out_path = NULL;
  char *file_pin = NULL;

  int do_to_pkcs8 = 0;
  int do_to_bind = 0;
  int action = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_TOPKCS8:
        do_to_pkcs8 = 1;
        action++;
        break;
      case OPT_TOBIND:
        do_to_bind = 1;
        action++;
        break;
      case OPT_IN:
        in_path = optarg;
        break;
      case OPT_OUT:
        out_path = optarg;
        break;
      case OPT_PIN:
        file_pin = optarg;
        break;
      case OPT_HELP:
      case 'h':
      default:
        usage();
        exit(0);
        break;
    }
  }

  // No action given, display the usage.
  if(action == 0) {
    usage();
    exit(0);
  }

  // Init the Botan crypto library
  LibraryInitializer::initialize();

  // We should convert to PKCS#8
  if(do_to_pkcs8) {
    to_pkcs8(in_path, out_path, file_pin);
  }

  // We should convert to BIND
  if(do_to_bind) {
    to_bind(in_path, out_path);
  }

  // Deinitialize the Botan crypto lib
  LibraryInitializer::deinitialize();

  return 0;
}

// Convert from BIND to PKCS#8

void to_pkcs8(char *in_path, char *out_path, char *file_pin) {
  FILE *file_pointer = NULL;
  char line[MAX_LINE], data[MAX_LINE], *value_pointer;
  int lineno = 0, m, n, error = 0, found, algorithm = -1, data_length;
  uint32_t bitfield = 0;

  BigInt bigN = BigInt(0);
  BigInt bigE = BigInt(0);
  BigInt bigD = BigInt(0);
  BigInt bigP = BigInt(0);
  BigInt bigQ = BigInt(0);
  BigInt bigDP = BigInt(0);
  BigInt bigDQ = BigInt(0);
  BigInt bigDX = BigInt(0);
  BigInt bigDG = BigInt(0);

  if(in_path == NULL) {
    fprintf(stderr, "Error: A path to the input file must be supplied. Use --in <path>\n");
    return;
  }

  if(out_path == NULL) {
    fprintf(stderr, "Error: A path to the output file must be supplied. Use --out <path>\n");
    return;
  }

  file_pointer = fopen(in_path, "r");
  if(!file_pointer) {
    fprintf(stderr, "Error: Could not open input file %.100s for reading.\n", in_path);
    return;
  }

  // Loop over all of the lines
  while(fgets(line, MAX_LINE, file_pointer) != NULL) {
    lineno++;

    // Find the current text field in the BIND file.
    for(m = 0, found = -1; found == -1 && file_tags[m]; m++) {
      if(strncasecmp(line, file_tags[m], strlen(file_tags[m])) == 0) {
        found = m;
      }
    }

    // The text files is not recognized.
    if(found == -1) {
      fprintf(stderr, "Error: Unrecognized input line %i\n", lineno);
      fprintf(stderr, "Error: --> %s", line);
      continue;
    }

    // Point to the data for this text field.
    value_pointer = line + strlen(file_tags[found]) + 1;
    // Continue if we are at the end of the string
    if(*value_pointer == 0) {
      continue;
    }

    // Check that we do not get duplicates.
    if(bitfield & (1 << found)) {
      fprintf(stderr, "Duplicate \"%s\" field, line %i - ignored\n", file_tags[found], lineno);
      continue;
    }
    bitfield |= (1 << found);

    // Handle the data for this text field.
    switch(found) {
      case TAG_VERSION:
        if(sscanf(value_pointer, "v%i.%i", &m, &n) != 2) {
          fprintf(stderr, "Error: Invalid/unknown version string (%.100s).\n", value_pointer);
          error = 1;
          break;
        }
        if(m != FILE_MAJOR_VERSION || n != FILE_MINOR_VERSION) {
          fprintf(stderr, "Error: Cannot parse this version of file format, v%i.%i.\n", m, n);
          error = 1;
        }
        break;
      case TAG_ALGORITHM:
        algorithm = strtol(value_pointer, NULL, 10);
        break;
      case TAG_MODULUS:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigN = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PUBEXP:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigE = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PRIVEXP:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigD = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PRIME1:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigP = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PRIME2:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigQ = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PRIME:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDP = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_SUBPRIME:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDQ = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_BASE:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDG = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      case TAG_PRIVVAL:
        data_length = b64_pton(value_pointer, (u_char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDX = BigInt((byte*)data, (u32bit)data_length);
        }
        break;
      // We do not need them
      case TAG_EXP1:
      case TAG_EXP2:
      case TAG_COEFF:
      case TAG_PUBVAL:
      default:
        break;
    }
  }

  // Something went wrong. Clean up and quit.
  if(error) {
    return;
  }

  // Save the the key to the disk
  switch(algorithm) {
    case -1:
      fprintf(stderr, "Error: The algorithm was not given in the file.\n", algorithm);
      break;
    case DNS_KEYALG_RSAMD5:
    case DNS_KEYALG_RSASHA1:
      save_rsa_pkcs8(out_path, file_pin, bigN, bigE, bigD, bigP, bigQ);
      break;
    case DNS_KEYALG_DSA:
      save_dsa_pkcs8(out_path, file_pin, bigDP, bigDQ, bigDG, bigDX);
      break;
    default:
      fprintf(stderr, "Error: The algorithm %i is not supported.\n", algorithm);
      break;
  }

  return;
}

// Convert from PKCS#8 to BIND

void to_bind(char *in_path, char *out_path) {
  if(in_path == NULL) {
    fprintf(stderr, "Error: A path to the input file must be supplied. Use --in <path>\n");
    return;
  }

  if(out_path == NULL) {
    fprintf(stderr, "Error: A path to the output file must be supplied. Use --out <path>\n");
    return;
  }

  fprintf(stderr, "Error: Function not implemented.\n");

  return;
}

// Save the RSA key as a PKCS#8 file

void save_rsa_pkcs8(char *out_path, char *file_pin, BigInt bigN, BigInt bigE, 
                    BigInt bigD, BigInt bigP, BigInt bigQ) {

  // See if the key material was found. Not checking D and N,
  // because they can be reconstructed if they are zero.
  if(bigE.is_zero() || bigP.is_zero() || bigQ.is_zero()) {
    fprintf(stderr, "Error: Some parts of the key material is missing in the input file.\n");
    return;
  }

  char buffer[MAX_LINE];

  Private_Key *priv_key = NULL;
  AutoSeeded_RNG *rng = new AutoSeeded_RNG();

  try {
    priv_key = new RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not extract the private key from the file.\n");
    delete rng;
    return;
  }

  std::ofstream priv_file(out_path);
  if(!priv_file) {
    fprintf(stderr, "Error: Could not open file for output.\n");
    delete rng;
    delete priv_key;
    return;
  }

  try {
    if(file_pin == NULL) {
      priv_file << PKCS8::PEM_encode(*priv_key);
    } else {
      priv_file << PKCS8::PEM_encode(*priv_key, *rng, file_pin);
    }

    printf("The key has been written to %s\n", out_path);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not write to file.\n");
  }
	
  delete rng;
  delete priv_key;
  priv_file.close();

  return;
}

// Save the DSA key as a PKCS#8 file

void save_dsa_pkcs8(char *out_path, char *file_pin, BigInt bigDP, BigInt bigDQ, 
                    BigInt bigDG, BigInt bigDX) {

  // See if the key material was found. Not checking Q and X
  // because it can be reconstructed if it is zero.
  if(bigDP.is_zero() || bigDG.is_zero() || bigDX.is_zero()) {
    fprintf(stderr, "Error: Some parts of the key material is missing in the input file.\n");
    return;
  }

  char buffer[MAX_LINE];

  Private_Key *priv_key = NULL;
  AutoSeeded_RNG *rng = new AutoSeeded_RNG();

  try {
    priv_key = new DSA_PrivateKey(*rng, DL_Group(bigDP, bigDQ, bigDG), bigDX);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not extract the private key from the file.\n");
    delete rng;
    return;
  }

  std::ofstream priv_file(out_path);
  if(!priv_file) {
    fprintf(stderr, "Error: Could not open file for output.\n");
    delete rng;
    delete priv_key;
    return;
  }

  try {
    if(file_pin == NULL) {
      priv_file << PKCS8::PEM_encode(*priv_key);
    } else {
      priv_file << PKCS8::PEM_encode(*priv_key, *rng, file_pin);
    }

    printf("The key has been written to %s\n", out_path);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not write to file.\n");
  }
	
  delete rng;
  delete priv_key;
  priv_file.close();

  return;
}
