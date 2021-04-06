/* This file is auto-generated from pkcs11_5_14_message_sign.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.14 Message-based signing and MACing functions */

CK_RV
C_MessageSignInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signing mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signing key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_SignMessage
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pData,            /* data to sign */
  CK_ULONG ulDataLen,           /* data to sign length */
  CK_BYTE_PTR pSignature,       /* gets signature */
  CK_ULONG_PTR pulSignatureLen  /* gets signature length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_SignMessageBegin
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen      /* length of message specific parameter */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_SignMessageNext
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_VOID_PTR pParameter,       /* message specific parameter */
  CK_ULONG ulParameterLen,      /* length of message specific parameter */
  CK_BYTE_PTR pData,            /* data to sign */
  CK_ULONG ulDataLen,           /* data to sign length */
  CK_BYTE_PTR pSignature,       /* gets signature */
  CK_ULONG_PTR pulSignatureLen  /* gets signature length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_MessageSignFinal
(
  CK_SESSION_HANDLE hSession        /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
