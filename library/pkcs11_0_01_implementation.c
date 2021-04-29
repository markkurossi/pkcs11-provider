/* This file is auto-generated from pkcs11_0_01_implementation.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 0.1 Implementation specific functions */

CK_RV
C_ImplOpenSession
(
  CK_ULONG          ulProviderID,
  CK_SESSION_HANDLE hSession
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0000101);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, ulProviderID);
  vp_buffer_add_uint32(&buf, hSession);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

CK_RV
C_ImplCloseSession
(
  CK_SESSION_HANDLE hSession
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = vp_global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0000102);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, hSession);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}
