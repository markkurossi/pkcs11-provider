/* This file is auto-generated from pkcs11_5_06_session.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.6 Session management functions */

/* C_OpenSession opens a session between an application and a
 * token.
 */
CK_RV
C_OpenSession
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_CloseSession closes a session between an application and a
 * token.
 */
CK_RV
C_CloseSession
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_CloseAllSessions closes all sessions with a token. */
CK_RV
C_CloseAllSessions
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GetSessionInfo obtains information about the session. */
CK_RV
C_GetSessionInfo
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_SessionCancel terminates active session based operations. */
CK_RV
C_SessionCancel
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_FLAGS          flags      /* flags control which sessions are cancelled */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
CK_RV
C_GetOperationState
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
CK_RV
C_SetOperationState
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_Login logs a user into a token. */
CK_RV
C_Login
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_LoginUser logs a user into a token. */
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

/* C_Logout logs a user out from a token. */
CK_RV
C_Logout
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
