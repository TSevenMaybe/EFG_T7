/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
   @file ofb_getiv.c
   F8 implementation, get IV, Tom St Denis
*/

#ifdef LTC_F8_MODE

/**
   Get the current initialization vector
   @param IV   [out] The destination of the initialization vector
   @param len  [in/out]  The max size and resulting size of the initialization vector
   @param f8   The F8 state
   @return CRYPT_OK if successful
*/
int f8_getiv(unsigned char *IV, unsigned long *len, const symmetric_F8 *f8)
{
   LTC_ARGCHK(IV  != NULL);
   LTC_ARGCHK(len != NULL);
   LTC_ARGCHK(f8  != NULL);
   if ((unsigned long)f8->blocklen > *len) {
      *len = f8->blocklen;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(IV, f8->IV, f8->blocklen);
   *len = f8->blocklen;

   return CRYPT_OK;
}

#endif
