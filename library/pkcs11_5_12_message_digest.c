/* This file is auto-generated from pkcs11_5_12_message_digest.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (c) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.12 Message digesting functions */

/* C_DigestInit initializes a message-digesting operation. */
CK_RV
C_DigestInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
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
  vp_buffer_add_uint32(&buf, 0xc0050c01);
  vp_buffer_add_space(&buf, 4);

  ret = vp_encode_mechanism(&buf, pMechanism);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_Digest digests data in a single part. */
CK_RV
C_Digest
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
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
  vp_buffer_add_uint32(&buf, 0xc0050c02);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pData, ulDataLen);

  if (pDigest == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulDigestLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pDigest == NULL)
      {
        *pulDigestLen = count;
      }
    else if (count > *pulDigestLen)
      {
        *pulDigestLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulDigestLen = count;
        vp_buffer_get_byte_arr(&buf, pDigest, count);
      }
  }

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_RV
C_DigestUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
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
  vp_buffer_add_uint32(&buf, 0xc0050c03);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pPart, ulPartLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_RV
C_DigestKey
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_RV
C_DigestFinal
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
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
  vp_buffer_add_uint32(&buf, 0xc0050c05);
  vp_buffer_add_space(&buf, 4);


  if (pDigest == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulDigestLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pDigest == NULL)
      {
        *pulDigestLen = count;
      }
    else if (count > *pulDigestLen)
      {
        *pulDigestLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulDigestLen = count;
        vp_buffer_get_byte_arr(&buf, pDigest, count);
      }
  }

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}
