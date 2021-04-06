/* This file is auto-generated from pkcs11_5_19_random.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.19 Random number generation functions */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
CK_RV
C_SeedRandom
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateRandom generates random data. */
CK_RV
C_GenerateRandom
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}