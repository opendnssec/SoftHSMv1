/*
 * Copyright (c) 2009-2011 .SE (The Internet Infrastructure Foundation).
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
  printf("  --topkcs8           Convert from BIND .private-key format to PKCS#8.\n");
  printf("                          Use with --in, --out, and --pin.\n");
  printf("  --tobind            Convert from PKCS#8 to BIND .private-key format.\n");
  printf("                          Use with --in, --pin, --name, --ttl, --ksk,\n");
  printf("                          and --algorithm.\n");
  printf("  --algorithm <alg>   Specifies which DNSSEC algorithm to use in file.\n");
  printf("                           RSAMD5\n");
  printf("                           DSA\n");
  printf("                           RSASHA1\n");
  printf("                           RSASHA1-NSEC3-SHA1\n");
  printf("                           DSA-NSEC3-SHA1\n");
  printf("                           RSASHA256\n");
  printf("                           RSASHA512\n");
  printf("  -h                  Shows this help screen.\n");
  printf("  --help              Shows this help screen.\n");
  printf("  --in <path>         The path to the input file.\n");
  printf("  --ksk               Set the flag to 257. Key Signing Key. Optional.\n");
  printf("  --name <name>       The owner name. Do not forget the trailing dot,\n");
  printf("                      e.g. \"example.com.\"\n");
  printf("  --out <path>        The path to the output file.\n");
  printf("  --pin <PIN>         To encrypt/decrypt PKCS#8 file. Optional.\n");
  printf("  --ttl <ttl>         The TTL to use for the DNSKEY RR. Optional.\n");
  printf("  -v                  Show version info.\n");
  printf("  --version           Show version info.\n");
  printf("\n");
  printf("  The following files will be created:\n");
  printf("    K<name>+<alg id>+<key tag>.key\tPublic key in RR format\n");
  printf("    K<name>+<alg id>+<key tag>.private\tPrivate key in key format\n");
  printf("  E.g.\n");
  printf("    Kexample.com.+007+05474.private\n");
}

// Give a number to each option
enum {
  OPT_TOPKCS8 = 0x100,
  OPT_TOBIND,
  OPT_ALGORITHM,
  OPT_HELP,
  OPT_IN,
  OPT_KSK,
  OPT_NAME,
  OPT_OUT,
  OPT_PIN,
  OPT_TTL,
  OPT_VERSION
};

// Define the options
static const struct option long_options[] = {
  { "topkcs8",    0, NULL, OPT_TOPKCS8 },
  { "tobind",     0, NULL, OPT_TOBIND },
  { "algorithm",  1, NULL, OPT_ALGORITHM },
  { "help",       0, NULL, OPT_HELP },
  { "in",         1, NULL, OPT_IN },
  { "ksk",        0, NULL, OPT_KSK },
  { "name",       1, NULL, OPT_NAME },
  { "out",        1, NULL, OPT_OUT },
  { "pin",        1, NULL, OPT_PIN },
  { "ttl",        1, NULL, OPT_TTL },
  { "version",    0, NULL, OPT_VERSION },
  { NULL,         0, NULL, 0 }
};

int main(int argc, char *argv[]) {
  int option_index = 0;
  int opt;

  char *in_path = NULL;
  char *out_path = NULL;
  char *file_pin = NULL;
  char *algorithm_str = NULL;
  char *name = NULL;

  int do_to_pkcs8 = 0;
  int do_to_bind = 0;
  int action = 0;
  int key_flag = 256;
  int ttl = 3600;
  int status = 0;

  while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
    switch (opt) {
      case OPT_TOPKCS8:
        do_to_pkcs8 = 1;
        action++;
        break;
      case OPT_TOBIND:
        do_to_bind = 1;
        action++;
        break;
      case OPT_ALGORITHM:
        algorithm_str = optarg;
        break;
      case OPT_IN:
        in_path = optarg;
        break;
      case OPT_KSK:
        key_flag = 257;
        break;
      case OPT_NAME:
        name = optarg;
        break;
      case OPT_OUT:
        out_path = optarg;
        break;
      case OPT_PIN:
        file_pin = optarg;
        break;
      case OPT_TTL:
        ttl = atoi(optarg);
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
  }

  // Init the Botan crypto library
  Botan::LibraryInitializer::initialize();

  // We should convert to PKCS#8
  if(do_to_pkcs8) {
    status = to_pkcs8(in_path, out_path, file_pin);
  }

  // We should convert to BIND
  if(do_to_bind) {
    status = to_bind(in_path, file_pin, name, ttl, key_flag, algorithm_str);
  }

  // Deinitialize the Botan crypto lib
  Botan::LibraryInitializer::deinitialize();

  return status;
}

// Convert from BIND to PKCS#8

int to_pkcs8(char *in_path, char *out_path, char *file_pin) {
  FILE *file_pointer = NULL;
  char line[MAX_LINE], data[MAX_LINE], *value_pointer;
  int lineno = 0, m, n, error = 0, found, algorithm = DNS_KEYALG_ERROR, data_length;
  uint32_t bitfield = 0;
  int status = 0;

  Botan::BigInt bigN = Botan::BigInt(0);
  Botan::BigInt bigE = Botan::BigInt(0);
  Botan::BigInt bigD = Botan::BigInt(0);
  Botan::BigInt bigP = Botan::BigInt(0);
  Botan::BigInt bigQ = Botan::BigInt(0);
  Botan::BigInt bigDP = Botan::BigInt(0);
  Botan::BigInt bigDQ = Botan::BigInt(0);
  Botan::BigInt bigDX = Botan::BigInt(0);
  Botan::BigInt bigDG = Botan::BigInt(0);

  if(in_path == NULL) {
    fprintf(stderr, "Error: A path to the input file must be supplied. Use --in <path>\n");
    return 1;
  }

  if(out_path == NULL) {
    fprintf(stderr, "Error: A path to the output file must be supplied. Use --out <path>\n");
    return 1;
  }

  file_pointer = fopen(in_path, "r");
  if(!file_pointer) {
    fprintf(stderr, "Error: Could not open input file %.100s for reading.\n", in_path);
    return 1;
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
        if(m > FILE_MAJOR_VERSION_MAX || (m == FILE_MAJOR_VERSION_MAX && n > FILE_MINOR_VERSION_MAX)) {
          fprintf(stderr, "Error: Cannot parse this version of file format, v%i.%i.\n", m, n);
          error = 1;
        }
        break;
      case TAG_ALGORITHM:
        algorithm = strtol(value_pointer, NULL, 10);
        break;
      case TAG_MODULUS:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigN = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PUBEXP:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigE = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PRIVEXP:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigD = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PRIME1:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigP = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PRIME2:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigQ = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PRIME:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDP = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_SUBPRIME:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDQ = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_BASE:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDG = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      case TAG_PRIVVAL:
        data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
        if(data_length == -1) {
          error = 1;
          fprintf(stderr, "Error: Could not parse the base64 string on line %i.\n", lineno);
        } else {
          bigDX = Botan::BigInt((Botan::byte*)data, (Botan::u32bit)data_length);
        }
        break;
      // We do not need them
      case TAG_EXP1:
      case TAG_EXP2:
      case TAG_COEFF:
      case TAG_PUBVAL:
      case TAG_CREATED:
      case TAG_PUBLISH:
      case TAG_ACTIVATE:
      default:
        break;
    }
  }

  fclose(file_pointer);

  // Something went wrong. Clean up and quit.
  if(error) {
    return 1;
  }

  // Save the the key to the disk
  switch(algorithm) {
    case DNS_KEYALG_ERROR:
      fprintf(stderr, "Error: The algorithm %i was not given in the file.\n", algorithm);
      status = 1;
      break;
    case DNS_KEYALG_RSAMD5:
    case DNS_KEYALG_RSASHA1:
    case DNS_KEYALG_RSASHA1_NSEC3_SHA1:
    case DNS_KEYALG_RSASHA256:
    case DNS_KEYALG_RSASHA512:
      status = save_rsa_pkcs8(out_path, file_pin, bigN, bigE, bigD, bigP, bigQ);
      break;
    case DNS_KEYALG_DSA:
    case DNS_KEYALG_DSA_NSEC3_SHA1:
      status = save_dsa_pkcs8(out_path, file_pin, bigDP, bigDQ, bigDG, bigDX);
      break;
    default:
      fprintf(stderr, "Error: The algorithm %i is not supported.\n", algorithm);
      status = 1;
      break;
  }

  return status;
}

// Convert from PKCS#8 to BIND

int to_bind(char *in_path, char *file_pin, char *name, int ttl, int key_flag, char *algorithm_str) {
  int algorithm;
  Botan::Private_Key *priv_key;
  int status = 0;

  if(in_path == NULL) {
    fprintf(stderr, "Error: A path to the input file must be supplied. Use --in <path>\n");
    return 1;
  }

  if(name == NULL) {
    fprintf(stderr, "Error: The name of the zone must be supplied. Use --name <zone>\n");
    return 1;
  }

  if(algorithm_str == NULL) {
    fprintf(stderr, "Error: An algorithm must be supplied. Use --algorithm <algo>\n");
    return 1;
  }

  // Get private key from PKCS8
  priv_key = key_from_pkcs8(in_path, file_pin);
  if(priv_key == NULL) {
    return 1;
  }

  // Determine which algorithm to use
  algorithm = get_key_algorithm(priv_key, algorithm_str);

  // Save keys to disk
  switch(algorithm) {
    case DNS_KEYALG_ERROR:
      fprintf(stderr, "Error: The algorithm was not given in the file.\n");
      status = 1;
      break;
    case DNS_KEYALG_RSAMD5:
    case DNS_KEYALG_RSASHA1:
    case DNS_KEYALG_RSASHA1_NSEC3_SHA1:
    case DNS_KEYALG_RSASHA256:
    case DNS_KEYALG_RSASHA512:
      status = save_rsa_bind(name, ttl, priv_key, key_flag, algorithm);
      break;
    case DNS_KEYALG_DSA:
    case DNS_KEYALG_DSA_NSEC3_SHA1:
      status = save_dsa_bind(name, ttl, priv_key, key_flag, algorithm);
      break;
    default:
      fprintf(stderr, "Error: The algorithm %i is not supported.\n", algorithm);
      status = 1;
      break;
  }

  delete priv_key;

  return status;
}

// Save the RSA key as a PKCS#8 file

int save_rsa_pkcs8(char *out_path, char *file_pin, Botan::BigInt bigN, Botan::BigInt bigE,
                    Botan::BigInt bigD, Botan::BigInt bigP, Botan::BigInt bigQ) {

  Botan::Private_Key *priv_key = NULL;
  Botan::AutoSeeded_RNG *rng;
  int status = 0;

  // See if the key material was found. Not checking D and N,
  // because they can be reconstructed if they are zero.
  if(bigE.is_zero() || bigP.is_zero() || bigQ.is_zero()) {
    fprintf(stderr, "Error: Some parts of the key material is missing in the input file.\n");
    return 1;
  }

  rng = new Botan::AutoSeeded_RNG();

  try {
    priv_key = new Botan::RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not extract the private key from the file.\n");
    delete rng;
    return 1;
  }

  std::ofstream priv_file(out_path);
  if(!priv_file) {
    fprintf(stderr, "Error: Could not open file for output.\n");
    delete rng;
    delete priv_key;
    return 1;
  }

  try {
    if(file_pin == NULL) {
      priv_file << Botan::PKCS8::PEM_encode(*priv_key);
    } else {
      priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin);
    }

    printf("The key has been written to %s\n", out_path);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not write to file.\n");
    status = 1;
  }

  delete rng;
  delete priv_key;
  priv_file.close();

  return status;
}

// Save the DSA key as a PKCS#8 file

int save_dsa_pkcs8(char *out_path, char *file_pin, Botan::BigInt bigDP, Botan::BigInt bigDQ, 
                    Botan::BigInt bigDG, Botan::BigInt bigDX) {

  Botan::Private_Key *priv_key = NULL;
  Botan::AutoSeeded_RNG *rng;
  int status = 0;

  // See if the key material was found. Not checking Q and X
  // because it can be reconstructed if it is zero.
  if(bigDP.is_zero() || bigDG.is_zero() || bigDX.is_zero()) {
    fprintf(stderr, "Error: Some parts of the key material is missing in the input file.\n");
    return 1;
  }

  rng = new Botan::AutoSeeded_RNG();

  try {
    priv_key = new Botan::DSA_PrivateKey(*rng, Botan::DL_Group(bigDP, bigDQ, bigDG), bigDX);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not extract the private key from the file.\n");
    delete rng;
    return 1;
  }

  std::ofstream priv_file(out_path);
  if(!priv_file) {
    fprintf(stderr, "Error: Could not open file for output.\n");
    delete rng;
    delete priv_key;
    return 1;
  }

  try {
    if(file_pin == NULL) {
      priv_file << Botan::PKCS8::PEM_encode(*priv_key);
    } else {
      priv_file << Botan::PKCS8::PEM_encode(*priv_key, *rng, file_pin);
    }

    printf("The key has been written to %s\n", out_path);
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Could not write to file.\n");
    status = 1;
  }

  delete rng;
  delete priv_key;
  priv_file.close();

  return status;
}

// Extract the private key from the PKCS#8 file

Botan::Private_Key* key_from_pkcs8(char *in_path, char *file_pin) {
  Botan::AutoSeeded_RNG *rng;
  Botan::Private_Key *priv_key = NULL;

  if(in_path == NULL) {
    return NULL;
  }

  rng = new Botan::AutoSeeded_RNG();

  try {
    if(file_pin == NULL) {
      priv_key = Botan::PKCS8::load_key(in_path, *rng);
    } else {
      priv_key = Botan::PKCS8::load_key(in_path, *rng, file_pin);
    }
  }
  catch(std::exception& e) {
    fprintf(stderr, "%s\n", e.what());
    fprintf(stderr, "Error: Perhaps wrong path to file, wrong file format, or wrong PIN to file (--pin <PIN>).\n");
    delete rng;
    return NULL;
  }
  delete rng;

  return priv_key;
}

// Return the correct DNSSEC key algorithm.
// Check that the given algorithm matches one of the supported ones and
// matches the algorithm of the key from the PKCS#8 file.

int get_key_algorithm(Botan::Private_Key *priv_key, char *algorithm_str) {
  if(priv_key == NULL || algorithm_str == NULL) {
    return DNS_KEYALG_ERROR;
  }

  // Compare with the longest string first, so that we do not get a false positive.

  if(strncmp(algorithm_str, "RSASHA1-NSEC3-SHA1", 18) == 0) {
    if(priv_key->algo_name().compare("RSA") == 0) {
      return DNS_KEYALG_RSASHA1_NSEC3_SHA1;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "DSA-NSEC3-SHA1", 14) == 0) {
    if(priv_key->algo_name().compare("DSA") == 0) {
      return DNS_KEYALG_DSA_NSEC3_SHA1;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "RSASHA256", 9) == 0) {
    if(priv_key->algo_name().compare("RSA") == 0) {
      return DNS_KEYALG_RSASHA256;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "RSASHA512", 9) == 0) {
    if(priv_key->algo_name().compare("RSA") == 0) {
      return DNS_KEYALG_RSASHA512;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "RSASHA1", 7) == 0) {
    if(priv_key->algo_name().compare("RSA") == 0) {
      return DNS_KEYALG_RSASHA1;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "RSAMD5", 6) == 0) {
    if(priv_key->algo_name().compare("RSA") == 0) {
      return DNS_KEYALG_RSAMD5;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  if(strncmp(algorithm_str, "DSA", 3) == 0) {
    if(priv_key->algo_name().compare("DSA") == 0) {
      return DNS_KEYALG_DSA;
    } else {
      fprintf(stderr, "Error: The given algorithm does not match the algorithm in the PKCS#8 file.\n");
      return DNS_KEYALG_ERROR;
    }
  }

  fprintf(stderr, "Error: The given algorithm \"%s\" is not known.\n", algorithm_str);

  return DNS_KEYALG_ERROR;
}

// Save the private RSA key in BIND format

int save_rsa_bind(char *name, int ttl, Botan::Private_Key *priv_key, int key_flag, int algorithm) {
  FILE *file_pointer;
  Botan::IF_Scheme_PrivateKey *if_key_priv;
  char priv_out[MAX_LINE], pub_out[MAX_LINE];
  unsigned char rdata[MAX_LINE];
  int key_tag, rdata_size;
  int status = 0;

  if(name == NULL || priv_key == NULL) {
    fprintf(stderr, "Error: save_rsa_bind: Got NULL as an argument.\n");
    return 1;
  }

  if(priv_key->algo_name().compare("RSA") != 0) {
    fprintf(stderr, "Error: save_rsa_bind: Got key with wrong algorithm. Got %s.\n", priv_key->algo_name().c_str());
    return 1;
  }

  // Create RDATA
  rdata_size = create_rsa_rdata(rdata, MAX_LINE, priv_key, key_flag, algorithm);
  if(rdata_size < 0) {
    fprintf(stderr, "Error: save_rsa_bind: Could not create RDATA.\n");
    return 1;
  }

  // Get the key tag
  key_tag = keytag(rdata, rdata_size);

  // Create the file names
  snprintf(priv_out, MAX_LINE, "K%s+%03i+%05i.private", name, algorithm, key_tag);
  snprintf(pub_out, MAX_LINE, "K%s+%03i+%05i.key", name, algorithm, key_tag);

  // Create the private key file

  file_pointer = fopen(priv_out, "w");
  if (!file_pointer) {
    fprintf(stderr, "Error: Could not open output file %.100s for writing.\n", priv_out);
    return 1;
  }

  // File version
  fprintf(file_pointer, "%s v%i.%i\n", file_tags[TAG_VERSION], FILE_MAJOR_VERSION, FILE_MINOR_VERSION);

  // Algorithm
  switch(algorithm) {
    case DNS_KEYALG_RSAMD5:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_RSAMD5, "RSA");
      break;
    case DNS_KEYALG_RSASHA1:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_RSASHA1, "RSASHA1");
      break;
    case DNS_KEYALG_RSASHA1_NSEC3_SHA1:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_RSASHA1_NSEC3_SHA1, "RSASHA1-NSEC3-SHA1");
      break;
    case DNS_KEYALG_RSASHA256:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_RSASHA256, "RSASHA256");
      break;
    case DNS_KEYALG_RSASHA512:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_RSASHA512, "RSASHA512");
      break;
    case DNS_KEYALG_ERROR:
    default:
      // Will not happen
      fprintf(stderr, "Error: save_rsa_bind: Unknown algorithm tag.\n");
      break;
  }

  if_key_priv = dynamic_cast<Botan::IF_Scheme_PrivateKey*>(priv_key);

  // Key material
  print_big_int(file_pointer, file_tags[TAG_MODULUS], if_key_priv->get_n());
  print_big_int(file_pointer, file_tags[TAG_PUBEXP], if_key_priv->get_e());
  print_big_int(file_pointer, file_tags[TAG_PRIVEXP], if_key_priv->get_d());
  print_big_int(file_pointer, file_tags[TAG_PRIME1], if_key_priv->get_p());
  print_big_int(file_pointer, file_tags[TAG_PRIME2], if_key_priv->get_q());
  print_big_int(file_pointer, file_tags[TAG_EXP1], if_key_priv->get_d() % (if_key_priv->get_p() - 1));
  print_big_int(file_pointer, file_tags[TAG_EXP2], if_key_priv->get_d() % (if_key_priv->get_q() - 1));
  print_big_int(file_pointer, file_tags[TAG_COEFF], inverse_mod(if_key_priv->get_q(), if_key_priv->get_p()));

  fclose(file_pointer);

  printf("The private key has been written to %s\n", priv_out);

  // Create the public key file

  file_pointer = fopen(pub_out, "w");
  if (!file_pointer) {
    fprintf(stderr, "Error: Could not open output file %.100s for writing.\n", pub_out);
    return 1;
  }

  if(print_dnskey(file_pointer, name, ttl, rdata, rdata_size) == 0) {
    printf("The public key has been written to %s\n", pub_out);
  } else {
    fprintf(stderr, "Error: Could not write the public key to the file.\n");
    status = 1;
  }

  fclose(file_pointer);

  return status;
}

// Save the private DSA key in BIND format

int save_dsa_bind(char *name, int ttl, Botan::Private_Key *priv_key, int key_flag, int algorithm) {
  FILE *file_pointer;
  Botan::DL_Scheme_PrivateKey *dl_key_priv;
  char priv_out[MAX_LINE], pub_out[MAX_LINE];
  unsigned char rdata[MAX_LINE];
  int key_tag, rdata_size;
  int status = 0;

  if(name == NULL || priv_key == NULL) {
    fprintf(stderr, "Error: save_dsa_bind: Got NULL as an argument.\n");
    return 1;
  }

  if(priv_key->algo_name().compare("DSA") != 0) {
    fprintf(stderr, "Error: save_dsa_bind: Got key with wrong algorithm. Got %s.\n", priv_key->algo_name().c_str());
    return 1;
  }

  // Create RDATA
  rdata_size = create_dsa_rdata(rdata, MAX_LINE, priv_key, key_flag, algorithm);

  // Get the key tag
  key_tag = keytag(rdata, rdata_size);

  // Create the file names
  snprintf(priv_out, MAX_LINE, "K%s+%03i+%05i.private", name, algorithm, key_tag);
  snprintf(pub_out, MAX_LINE, "K%s+%03i+%05i.key", name, algorithm, key_tag);

  file_pointer = fopen(priv_out, "w");
  if (!file_pointer) {
    fprintf(stderr, "Error: Could not open output file %.100s for writing.\n", priv_out);
    return 1;
  }

  // File version
  fprintf(file_pointer, "%s v%i.%i\n", file_tags[TAG_VERSION], FILE_MAJOR_VERSION, FILE_MINOR_VERSION);

  // Algorithm
  switch(algorithm) {
    case DNS_KEYALG_DSA:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_DSA, "DSA");
      break;
    case DNS_KEYALG_DSA_NSEC3_SHA1:
      fprintf (file_pointer, "%s %i (%s)\n", file_tags[TAG_ALGORITHM], DNS_KEYALG_DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1");
      break;
    case DNS_KEYALG_ERROR:
    default:
      // Will not happen
      fprintf(stderr, "Error: save_dsa_bind: Unknown algorithm tag.\n");
      break;
  }

  dl_key_priv = dynamic_cast<Botan::DL_Scheme_PrivateKey*>(priv_key);

  // Key material
  print_big_int(file_pointer, file_tags[TAG_PRIME], dl_key_priv->group_p());
  print_big_int(file_pointer, file_tags[TAG_SUBPRIME], dl_key_priv->group_q());
  print_big_int(file_pointer, file_tags[TAG_BASE], dl_key_priv->group_g());
  print_big_int(file_pointer, file_tags[TAG_PRIVVAL], dl_key_priv->get_x());
  print_big_int(file_pointer, file_tags[TAG_PUBVAL], dl_key_priv->get_y());

  fclose(file_pointer);

  printf("The private key has been written to %s\n", priv_out);

  // Create the public key file

  file_pointer = fopen(pub_out, "w");
  if (!file_pointer) {
    fprintf(stderr, "Error: Could not open output file %.100s for writing.\n", pub_out);
    return 1;
  }

  if(print_dnskey(file_pointer, name, ttl, rdata, rdata_size) == 0) {
    printf("The public key has been written to %s\n", pub_out);
  } else {
    fprintf(stderr, "Could not write the public key to the file.\n");
    status = 1;
  }

  fclose(file_pointer);

  return status;
}

// Print the BigInt to file

void print_big_int(FILE *file_pointer, const char *file_tag, Botan::BigInt big_integer) {
  char bin_integer[MAX_LINE], base64_integer[MAX_LINE];
  int base64_len;

  if(file_pointer == NULL || file_tag == NULL) {
    fprintf(stderr, "Error: print_big_int: Got NULL as an argument.\n");
    return;
  }

  if(big_integer.bytes() >= MAX_LINE) {
    fprintf(stderr, "Error: print_big_int: Too big integer.\n");
    return;
  }

  // Convert to binary
  big_integer.binary_encode((Botan::byte *)bin_integer);

  // Convert to base64
  base64_len = b64_ntop((unsigned char*)bin_integer, big_integer.bytes(), base64_integer, MAX_LINE);
  if(base64_len < 0) {
    fprintf(stderr, "Error: print_big_int: Could not convert to base64.\n");
    return;
  }
  base64_integer[base64_len] = (char)0;

  // Print base64 to file
  fprintf(file_pointer, "%s %s\n", file_tag, base64_integer);

  return;
}

// Create RSA RDATA

int create_rsa_rdata(unsigned char *rdata, size_t length, Botan::Private_Key *priv_key, int key_flag, int algorithm) {
  size_t counter = 0, big_e_size, big_n_size;
  Botan::IF_Scheme_PrivateKey *if_key_priv;
  Botan::BigInt big_e;
  Botan::BigInt big_n;

  if(rdata == NULL || priv_key == NULL) {
    fprintf(stderr, "Error: create_rsa_rdata: Got NULL as an argument.\n");
    return -1;
  }

  // Key material
  if_key_priv = dynamic_cast<Botan::IF_Scheme_PrivateKey*>(priv_key);
  big_e = if_key_priv->get_e();
  big_n = if_key_priv->get_n();
  big_e_size = big_e.bytes();
  big_n_size = big_n.bytes();

  // Check length of buffer
  if((7 + big_e_size + big_n_size) > length) {
    fprintf(stderr, "Error: create_rsa_rdata: Buffer is too small.\n");
    return -1;
  }

  // Zone key
  rdata[counter++] = 1;

  // SEP flag
  if(key_flag == 257) {
    rdata[counter++] = 1;
  } else {
    rdata[counter++] = 0;
  }

  // Protocol
  rdata[counter++] = 3;

  // Algorithm
  rdata[counter++] = (unsigned char)algorithm;

  // Exponent length
  if(big_e_size <= 255) {
    rdata[counter++] = (unsigned char)big_e_size;
  } else {
    rdata[counter++] = 0;
    rdata[counter++] = (unsigned char)(big_e_size >> 8);
    rdata[counter++] = (unsigned char)big_e_size;
  }

  // Exponent
  big_e.binary_encode((Botan::byte*)(rdata + counter));
  counter += big_e_size;

  // Modulus
  big_n.binary_encode((Botan::byte*)(rdata + counter));
  counter += big_n_size;

  return counter;
}

// Create DSA RDATA

int create_dsa_rdata(unsigned char *rdata, size_t length, Botan::Private_Key *priv_key, int key_flag, int algorithm) {
  size_t counter = 0, size, size_parameter;
  Botan::DL_Scheme_PrivateKey *dl_key_priv;
  Botan::BigInt big_q;
  Botan::BigInt big_p;
  Botan::BigInt big_g;
  Botan::BigInt big_y;

  if(rdata == NULL || priv_key == NULL) {
    fprintf(stderr, "Error: create_dsa_rdata: Got NULL as an argument.\n");
    return -1;
  }

  // Key material
  dl_key_priv = dynamic_cast<Botan::DL_Scheme_PrivateKey*>(priv_key);
  big_q = dl_key_priv->group_q();
  big_p = dl_key_priv->group_p();
  big_g = dl_key_priv->group_g();
  big_y = dl_key_priv->get_y();
  size = big_g.bytes();
  size_parameter = (size - 64) / 8;

  // Check the value of T
  if(size_parameter > 8) {
    fprintf(stderr, "Error: create_dsa_rdata: No support for DSA T > 8.\n");
    return -1;
  }

  // Check length of buffer
  if((25 + 3 * size) > length) {
    fprintf(stderr, "Error: create_dsa_rdata: Buffer is too small.\n");
    return -1;
  }

  // Zone key
  rdata[counter++] = 1;

  // SEP flag
  if(key_flag == 257) {
    rdata[counter++] = 1;
  } else {
    rdata[counter++] = 0;
  }

  // Protocol
  rdata[counter++] = 3;

  // Algorithm
  rdata[counter++] = (unsigned char)algorithm;

  // T
  rdata[counter++] = (unsigned char)size_parameter;

  // Q
  big_q.binary_encode((Botan::byte*)(rdata + counter));
  counter += 20;

  // P
  big_p.binary_encode((Botan::byte*)(rdata + counter));
  counter += size;

  // G
  big_g.binary_encode((Botan::byte*)(rdata + counter));
  counter += size;

  // Y
  big_y.binary_encode((Botan::byte*)(rdata + counter));
  counter += size;

  return counter;
}

// Print the given information as an DNSKEY RR in the file.

int print_dnskey(FILE *file_pointer, char *name, int ttl, unsigned char *rdata, int rdata_size) {
  char base64[MAX_LINE];
  int base64_len;

  if(file_pointer == NULL || name == NULL || rdata == NULL) {
    fprintf(stderr, "Error: print_dnskey: Got NULL as an argument.\n");
    return -1;
  }

  if(rdata_size < 4) {
    fprintf(stderr, "Error: print_dnskey: The length of the RDATA is too small.\n");
    return -1;
  }

  // Convert to base64
  base64_len = b64_ntop(rdata + 4, rdata_size - 4, base64, MAX_LINE - 1);
  if(base64_len < 0) {
    fprintf(stderr, "Error: print_dnskey: Could not convert to base64.\n");
    return -1;
  }
  base64[base64_len] = (char)0;

  fprintf(file_pointer, "%s\t%i\tIN\tDNSKEY\t%i %i %i %s\n", name, ttl, (rdata[0] << 8) + rdata[1], rdata[2], rdata[3], base64);

  return 0;
}


/* From RFC4034, with some extra code
 *
 * Assumes that int is at least 16 bits.
 * First octet of the key tag is the most significant 8 bits of the
 * return value;
 * Second octet of the key tag is the least significant 8 bits of the
 * return value.
 */

unsigned int keytag(unsigned char key[], unsigned int keysize) {
  unsigned long ac;     /* assumed to be 32 bits or larger */
  unsigned int i;       /* loop index */

  if(keysize < 4) {
    return 0;
  }

  if (key[3] == DNS_KEYALG_RSAMD5) {
    ac = (key[keysize - 3] << 8) + key[keysize - 2];
  } else {
    for( ac = 0, i = 0; i < keysize; ++i ) {
      ac += (i & 1) ? key[i] : key[i] << 8;
    }

    ac += (ac >> 16) & 0xFFFF;
  }

  return ac & 0xFFFF;
}
