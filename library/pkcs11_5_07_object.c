/* This file is auto-generated from pkcs11_5_07_object.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.7 Object management functions */

/* C_CreateObject creates a new object. */
CK_RV
C_CreateObject
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
  CK_RV ret;
  VPBuffer buf;
  int i;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050701);
  vp_buffer_add_space(&buf, 4);

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

  *phObject = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_CopyObject copies an object, creating a new object for the
 * copy.
 */
CK_RV
C_CopyObject
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
  CK_RV ret;
  VPBuffer buf;
  int i;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050702);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, hObject);
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

  *phNewObject = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_DestroyObject destroys an object. */
CK_RV
C_DestroyObject
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050703);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, hObject);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_GetObjectSize gets the size of an object in bytes. */
CK_RV
C_GetObjectSize
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050704);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, hObject);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  *pulSize = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
CK_RV
C_GetAttributeValue
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
  /*
   * Session:
   *            CK_SESSION_HANDLE hSession
   * Inputs:
   *            CK_OBJECT_HANDLE  hObject
   *   [ulCount]CK_ATTRIBUTE      pTemplate
   * Outputs:
   *   [ulCount]CK_ATTRIBUTE      pTemplate
   */
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
CK_RV
C_SetAttributeValue
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
  CK_RV ret;
  VPBuffer buf;
  int i;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050706);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, hObject);
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

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
CK_RV
C_FindObjectsInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
  /*
   * Session:
   *            CK_SESSION_HANDLE hSession
   * Inputs:
   *   [ulCount]CK_ATTRIBUTE      pTemplate
   */
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
CK_RV
C_FindObjects
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
  /*
   * Session:
   *                   CK_SESSION_HANDLE hSession
   * Inputs:
   *                   CK_ULONG          ulMaxObjectCount
   * Outputs:
   *   [pulObjectCount]CK_OBJECT_HANDLE  phObject
   */
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
CK_RV
C_FindObjectsFinal
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050709);
  vp_buffer_add_space(&buf, 4);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_uninit(&buf);

  return ret;
}
