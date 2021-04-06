/* This file is auto-generated from pkcs11_5_09_message_encrypt.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.9 Message-based encryption functions */

CK_RV
C_MessageEncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_EncryptMessage
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
  CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
  CK_BYTE_PTR pPlaintext,       /* plain text  */
  CK_ULONG ulPlaintextLen,      /* plain text length */
  CK_BYTE_PTR pCiphertext,      /* gets cipher text */
  CK_ULONG_PTR pulCiphertextLen /* gets cipher text length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_EncryptMessageBegin
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
C_EncryptMessageNext
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_VOID_PTR pParameter,            /* message specific parameter */
  CK_ULONG ulParameterLen,           /* length of message specific parameter */
  CK_BYTE_PTR pPlaintextPart,        /* plain text */
  CK_ULONG ulPlaintextPartLen,       /* plain text length */
  CK_BYTE_PTR pCiphertextPart,       /* gets cipher text */
  CK_ULONG_PTR pulCiphertextPartLen, /* gets cipher text length */
  CK_FLAGS flags                     /* multi mode flag */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_MessageEncryptFinal
(
  CK_SESSION_HANDLE hSession        /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
