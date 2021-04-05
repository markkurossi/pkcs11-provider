/*
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
CK_RV
C_GetFunctionStatus
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel.
 */
CK_RV
C_CancelFunction
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_LoginUser
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen,  /* the length of the PIN */
  CK_UTF8CHAR_PTR   pUsername, /* the user's name */
  CK_ULONG          ulUsernameLen /*the length of the user's name */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_SessionCancel
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_FLAGS          flags      /* flags control which sessions are cancelled */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

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
