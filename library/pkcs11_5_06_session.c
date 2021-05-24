/* This file is auto-generated from pkcs11_5_06_session.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (c) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/***************************** Session registry *****************************/

struct VPSessionStruct
{
  struct VPSessionStruct *next;
  CK_SESSION_HANDLE id;
  VPIPCConn *session;
};

typedef struct VPSessionStruct VPSession;

#define VP_SESSIONS_HASH_SIZE 1024

static VPSession *sessions[VP_SESSIONS_HASH_SIZE];

static CK_RV
vp_session_register(VPIPCConn *session, CK_SESSION_HANDLE id)
{
  int idx = id % VP_SESSIONS_HASH_SIZE;
  VPSession *s;
  CK_RV ret;

  s = calloc(1, sizeof(*s));
  if (s == NULL)
    return CKR_HOST_MEMORY;

  s->id = id;
  s->session = session;

  ret = vp_init_args.LockMutex(vp_global_mutex);
  if (ret != CKR_OK)
    {
      free(s);
      return ret;
    }

  s->next = sessions[idx];
  sessions[idx] = s;

  vp_init_args.UnlockMutex(vp_global_mutex);

  return CKR_OK;
}

VPIPCConn *
vp_session(CK_SESSION_HANDLE id, CK_RV *ret)
{
  int idx = id % VP_SESSIONS_HASH_SIZE;
  VPSession *s;

  *ret = vp_init_args.LockMutex(vp_global_mutex);
  if (*ret != CKR_OK)
    return NULL;

  for (s = sessions[idx]; s != NULL; s = s->next)
    if (s->id == id)
      {
        *ret = vp_init_args.UnlockMutex(vp_global_mutex);
        return s->session;
      }

  *ret = vp_init_args.UnlockMutex(vp_global_mutex);
  if (*ret != CKR_OK)
    return NULL;

  *ret = CKR_SESSION_HANDLE_INVALID;

  return NULL;
}


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
  VPIPCConn *session;

  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = vp_global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050601);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_ulong(&buf, slotID);
  vp_buffer_add_uint32(&buf, flags);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  *phSession = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  /* Open session IPC channel. */
  session = vp_ipc_connect(SOCKET_PATH);
  if (session == NULL)
    {
      C_ImplCloseSession(*phSession);
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_REMOVED;
    }
  ret = vp_session_register(session, *phSession);
  if (ret != CKR_OK)
    {
      C_ImplCloseSession(*phSession);
      vp_buffer_uninit(&buf);
      return ret;
    }

  ret = C_ImplOpenSession(vp_provider_id, *phSession);
  if (ret != CKR_OK)
    {
      /* XXX remove session from storage */
      /* XXX uninit session object */
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_log(LOG_INFO, "SessionID:  %08lx", (unsigned long) *phSession);

  /* XXX store Notify+pApplication. */


  vp_buffer_uninit(&buf);

  return ret;
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
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050608);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, userType);
  vp_buffer_add_byte_arr(&buf, pPin, ulPinLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
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
