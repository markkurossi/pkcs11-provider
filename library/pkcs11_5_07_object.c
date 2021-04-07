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
  VPBuffer buf;
  unsigned char *data;
  int i;

  vp_buffer_init(&buf);

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
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
  VPBuffer buf;
  unsigned char *data;
  int i;

  vp_buffer_init(&buf);

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, hObject);
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_DestroyObject destroys an object. */
CK_RV
C_DestroyObject
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
  VPBuffer buf;
  unsigned char *data;

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, hObject);

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
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
  VPBuffer buf;
  unsigned char *data;

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, hObject);

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
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
  VPBuffer buf;
  unsigned char *data;
  int i;

  vp_buffer_init(&buf);

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, hObject);
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
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
  VPBuffer buf;
  unsigned char *data;
  int i;

  vp_buffer_init(&buf);

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, hObject);
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
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
  VPBuffer buf;
  unsigned char *data;
  int i;

  vp_buffer_init(&buf);

  vp_buffer_add_uint32(&buf, hSession);
  vp_buffer_add_uint32(&buf, ulCount);
  for (i = 0; i < ulCount; i++)
    {
      CK_ATTRIBUTE *iel = &pTemplate[i];

      vp_buffer_add_uint32(&buf, iel->type);
      vp_buffer_add_byte_arr(&buf, iel->pValue, iel->ulValueLen);
    }

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
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
  VPBuffer buf;
  unsigned char *data;

  vp_buffer_add_uint32(&buf, hSession);

  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  VP_FUNCTION_NOT_SUPPORTED;
}
