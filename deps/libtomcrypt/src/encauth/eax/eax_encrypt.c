/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/**
   @file eax_encrypt.c
   EAX implementation, encrypt block by Tom St Denis
*/
#include "tomcrypt_private.h"

#ifdef LTC_EAX_MODE

/**
   Encrypt with EAX a block of data.
   @param eax        The EAX state
   @param pt         The plaintext to encrypt
   @param ct         [out] The ciphertext as encrypted
   @param length     The length of the plaintext (octets)
   @return CRYPT_OK if successful
*/
int eax_encrypt(eax_state *eax, const unsigned char *pt, unsigned char *ct,
                unsigned long length)
{
   int err;

   LTC_ARGCHK(eax != NULL);
   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);

   /* encrypt */
   if ((err = ctr_encrypt(pt, ct, length, &eax->ctr)) != CRYPT_OK) {
      return err;
   }

   /* omac ciphertext */
   return omac_process(&eax->ctomac, ct, length);
}

#endif

