/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_RV
C_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_Encrypt encrypts single-part data. */
CK_RV
C_Encrypt
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_RV
C_EncryptUpdate
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_RV
C_EncryptFinal
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

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
