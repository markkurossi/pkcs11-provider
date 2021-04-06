/* This file is auto-generated from pkcs11_5_11_message_decrypt.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.11 Message-based decryption functions */

CK_RV
C_MessageDecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_DecryptMessage
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
  CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
  CK_BYTE_PTR pCiphertext,      /* cipher text */
  CK_ULONG ulCiphertextLen,     /* cipher text length */
  CK_BYTE_PTR pPlaintext,       /* gets plain text */
  CK_ULONG_PTR pulPlaintextLen  /* gets plain text length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_DecryptMessageBegin
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
  CK_ULONG ulAssociatedDataLen  /* AEAD Associated data length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_DecryptMessageNext
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pCiphertext,      /* cipher text */
  CK_ULONG ulCiphertextLen,     /* cipher text length */
  CK_BYTE_PTR pPlaintext,       /* gets plain text */
  CK_ULONG_PTR pulPlaintextLen,  /* gets plain text length */
  CK_FLAGS flags                /* multi mode flag */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_MessageDecryptFinal
(
  CK_SESSION_HANDLE hSession        /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
