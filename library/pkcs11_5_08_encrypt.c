/* This file is auto-generated from pkcs11_5_08_encrypt.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (c) 2020-2023 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.8 Encryption functions */

/* C_EncryptInit initializes an encryption operation. */
CK_RV
C_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
  CK_GCM_PARAMS_PTR gcm_params = NULL;
  CK_BYTE_PTR iv = NULL;
  CK_ULONG iv_len = 0;

  if (pMechanism->mechanism == CKM_AES_GCM
      && pMechanism->ulParameterLen == sizeof(CK_GCM_PARAMS))
    {
      gcm_params = (CK_GCM_PARAMS_PTR) pMechanism->pParameter;
      if (gcm_params == NULL)
        {
          vp_log(LOG_ERR, "CK_GCM_PARAMS is NULL");
          return CKR_MECHANISM_PARAM_INVALID;
        }
      if (gcm_params->ulIvBits == 0)
        {
          iv = gcm_params->pIv;
          iv_len = gcm_params->ulIvLen;
        }
    }

  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050801);
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

  vp_buffer_get_byte_arr(&buf, iv, iv_len);

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  if (gcm_params != NULL && gcm_params->ulIvBits == 0)
    gcm_params->ulIvBits = gcm_params->ulIvLen * 8;


  vp_buffer_uninit(&buf);

  return ret;
}

/* C_Encrypt encrypts single-part data. */
CK_RV
C_Encrypt
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
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
  vp_buffer_add_uint32(&buf, 0xc0050802);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pData, ulDataLen);

  if (pEncryptedData == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulEncryptedDataLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pEncryptedData == NULL)
      {
        *pulEncryptedDataLen = count;
      }
    else if (count > *pulEncryptedDataLen)
      {
        *pulEncryptedDataLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulEncryptedDataLen = count;
        vp_buffer_get_byte_arr(&buf, pEncryptedData, count);
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

/* C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_RV
C_EncryptUpdate
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
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
  vp_buffer_add_uint32(&buf, 0xc0050803);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pPart, ulPartLen);

  if (pEncryptedPart == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulEncryptedPartLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pEncryptedPart == NULL)
      {
        *pulEncryptedPartLen = count;
      }
    else if (count > *pulEncryptedPartLen)
      {
        *pulEncryptedPartLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulEncryptedPartLen = count;
        vp_buffer_get_byte_arr(&buf, pEncryptedPart, count);
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

/* C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_RV
C_EncryptFinal
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
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
  vp_buffer_add_uint32(&buf, 0xc0050804);
  vp_buffer_add_space(&buf, 4);


  if (pLastEncryptedPart == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulLastEncryptedPartLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    uint32_t count = vp_buffer_get_uint32(&buf);

    if (pLastEncryptedPart == NULL)
      {
        *pulLastEncryptedPartLen = count;
      }
    else if (count > *pulLastEncryptedPartLen)
      {
        *pulLastEncryptedPartLen = count;
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulLastEncryptedPartLen = count;
        vp_buffer_get_byte_arr(&buf, pLastEncryptedPart, count);
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
