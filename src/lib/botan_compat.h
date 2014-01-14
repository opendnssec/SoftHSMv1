/*
 * BigInt Base
 * (C) 1999-2008 Jack Lloyd
 *
 * Distributed under the terms of the Botan license
 */

#ifndef SOFTHSM_BOTAN_H
#define SOFTHSM_BOTAN_H 1

#include <botan/bigint.h>

namespace BotanCompat {

/* 
 * This function was accidently dropped in Botan.
 * Copied this function to SoftHSM so that all versions
 * of Botan will work with SoftHSM. 
 */

/**
 * Return the integer as an unsigned 32bit-integer-value. If the
 * value is negative OR to big to be stored in 32bits, this
 * function will throw an exception.
 * @result a 32bit-integer
 */
Botan::u32bit to_u32bit(const Botan::BigInt &n);

}

#endif /* SOFTHSM_BOTAN_H */
