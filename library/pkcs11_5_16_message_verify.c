/* This file is auto-generated from pkcs11_5_16_message_verify.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.16 Message-based functions for verifying signatures and MACs */

CK_RV
C_MessageVerifyInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signing mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signing key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_VerifyMessage
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pData,            /* data to sign */
  CK_ULONG ulDataLen,           /* data to sign length */
  CK_BYTE_PTR pSignature,       /* signature */
  CK_ULONG ulSignatureLen       /* signature length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_VerifyMessageBegin
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen      /* length of message specific parameter */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_VerifyMessageNext
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pData,            /* data to sign */
  CK_ULONG ulDataLen,           /* data to sign length */
  CK_BYTE_PTR pSignature,       /* signature */
  CK_ULONG ulSignatureLen       /* signature length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_MessageVerifyFinal
(
  CK_SESSION_HANDLE hSession        /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
