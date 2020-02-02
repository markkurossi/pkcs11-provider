/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_RV
C_DigestInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_Digest digests data in a single part. */
CK_RV
C_Digest
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_RV
C_DigestUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_RV
C_DigestKey
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_RV
C_DigestFinal
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
