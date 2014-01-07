/*
 * BigInt Base
 * (C) 1999-2008 Jack Lloyd
 *
 * Distributed under the terms of the Botan license
 */

#include "botan_compat.h"

namespace BotanCompat {

/* 
 * This function was accidently dropped in Botan.
 * Copied this function to SoftHSM so that all versions
 * of Botan will work with SoftHSM. 
 */

/*
* Convert this number to a u32bit, if possible
*/
Botan::u32bit to_u32bit(const Botan::BigInt &n)
   {
   if(n.is_negative())
      throw Botan::Encoding_Error("BigInt::to_u32bit: Number is negative");
   if(n.bits() >= 32)
      throw Botan::Encoding_Error("BigInt::to_u32bit: Number is too big to convert");

   Botan::u32bit out = 0;
   for(Botan::u32bit j = 0; j != 4; ++j)
      out = (out << 8) | n.byte_at(3-j);
   return out;
   }

}
