/* This file is auto-generated from pkcs11_5_10_decrypt.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.10 Decryption functions */

/* C_DecryptInit initializes a decryption operation. */
CK_RV
C_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_Decrypt decrypts encrypted data in a single part. */
CK_RV
C_Decrypt
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
CK_RV
C_DecryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
CK_RV
C_DecryptFinal
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
