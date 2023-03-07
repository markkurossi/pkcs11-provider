/* This file is auto-generated from pkcs11_5_10_decrypt.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (c) 2020-2023 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.10 Decryption functions */

/* C_DecryptInit initializes a decryption operation. */
CK_RV
C_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
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
  vp_buffer_add_uint32(&buf, 0xc0050a01);
  vp_buffer_add_space(&buf, 4);

  ret = vp_encode_mechanism(&buf, pMechanism);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }
  vp_buffer_add_uint32(&buf, hKey);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
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
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050a02);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pEncryptedData, ulEncryptedDataLen);

  if (pData == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulDataLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pData == NULL)
      {
        *pulDataLen = count;
      }
    else if (count > *pulDataLen)
      {
        *pulDataLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulDataLen = count;
        vp_buffer_get_byte_arr(&buf, pData, count);
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
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050a03);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pEncryptedPart, ulEncryptedPartLen);

  if (pPart == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulPartLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pPart == NULL)
      {
        *pulPartLen = count;
      }
    else if (count > *pulPartLen)
      {
        *pulPartLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulPartLen = count;
        vp_buffer_get_byte_arr(&buf, pPart, count);
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
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050a04);
  vp_buffer_add_space(&buf, 4);


  if (pLastPart == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulLastPartLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pLastPart == NULL)
      {
        *pulLastPartLen = count;
      }
    else if (count > *pulLastPartLen)
      {
        *pulLastPartLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulLastPartLen = count;
        vp_buffer_get_byte_arr(&buf, pLastPart, count);
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
