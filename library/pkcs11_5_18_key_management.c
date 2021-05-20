/* This file is auto-generated from pkcs11_5_18_key_management.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.18 Key management functions */

/* C_GenerateKey generates a secret key, creating a new key
 * object.
 */
CK_RV
C_GenerateKey
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  int i;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0051201);
  vp_buffer_add_space(&buf, 4);

  {
    CK_MECHANISM *iel = pMechanism;

    vp_buffer_add_uint32(&buf, iel->mechanism);
    vp_buffer_add_byte_arr(&buf, iel->pParameter, iel->ulParameterLen);
  }
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  *phKey = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
CK_RV
C_GenerateKeyPair
(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.  attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets priv. key handle */
)
{
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  int i;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Lookup session by hSession */
  conn = vp_session(hSession, &ret);
  if (ret != CKR_OK)
    return ret;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0051202);
  vp_buffer_add_space(&buf, 4);

  {
    CK_MECHANISM *iel = pMechanism;

    vp_buffer_add_uint32(&buf, iel->mechanism);
    vp_buffer_add_byte_arr(&buf, iel->pParameter, iel->ulParameterLen);
  }
  vp_buffer_add_uint32(&buf, ulPublicKeyAttributeCount);
  for (i = 0; i < ulPublicKeyAttributeCount; i++)
    {
      CK_ATTRIBUTE *iel = &pPublicKeyTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }
  vp_buffer_add_uint32(&buf, ulPrivateKeyAttributeCount);
  for (i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
      CK_ATTRIBUTE *iel = &pPrivateKeyTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  *phPublicKey = vp_buffer_get_uint32(&buf);
  *phPrivateKey = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV
C_WrapKey
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
CK_RV
C_UnwrapKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
CK_RV
C_DeriveKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
