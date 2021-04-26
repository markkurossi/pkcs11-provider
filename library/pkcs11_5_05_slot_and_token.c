/* This file is auto-generated from pkcs11_5_05_slot_and_token.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.5 Slot and token management function */

/* C_GetSlotList obtains a list of slots in the system. */
CK_RV
C_GetSlotList
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050501);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_bool(&buf, tokenPresent);

  if (pSlotList == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulCount);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }


  {
    uint32_t count = vp_buffer_get_uint32(&buf);
    uint32_t i;

    if (pSlotList == NULL)
      {
        *pulCount = count;
      }
    else if (count > *pulCount)
      {
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulCount = count;
        for (i = 0; i < count; i++)
          pSlotList[i] = vp_buffer_get_uint32(&buf);
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

/* C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
CK_RV
C_GetSlotInfo
(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050502);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, slotID);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    CK_SLOT_INFO *iel = pInfo;

    vp_buffer_get_byte_arr(&buf, iel->slotDescription, 64);
    vp_buffer_get_byte_arr(&buf, iel->manufacturerID, 32);
    iel->flags = vp_buffer_get_uint32(&buf);
    {
      CK_VERSION *jel = &iel->hardwareVersion;

      jel->major = vp_buffer_get_byte(&buf);
      jel->minor = vp_buffer_get_byte(&buf);
    }
    {
      CK_VERSION *jel = &iel->firmwareVersion;

      jel->major = vp_buffer_get_byte(&buf);
      jel->minor = vp_buffer_get_byte(&buf);
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

/* C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
CK_RV
C_GetTokenInfo
(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050503);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, slotID);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    CK_TOKEN_INFO *iel = pInfo;

    vp_buffer_get_byte_arr(&buf, iel->label, 32);
    vp_buffer_get_byte_arr(&buf, iel->manufacturerID, 32);
    vp_buffer_get_byte_arr(&buf, iel->model, 16);
    vp_buffer_get_byte_arr(&buf, iel->serialNumber, 16);
    iel->flags = vp_buffer_get_uint32(&buf);
    iel->ulMaxSessionCount = vp_buffer_get_uint32(&buf);
    iel->ulSessionCount = vp_buffer_get_uint32(&buf);
    iel->ulMaxRwSessionCount = vp_buffer_get_uint32(&buf);
    iel->ulRwSessionCount = vp_buffer_get_uint32(&buf);
    iel->ulMaxPinLen = vp_buffer_get_uint32(&buf);
    iel->ulMinPinLen = vp_buffer_get_uint32(&buf);
    iel->ulTotalPublicMemory = vp_buffer_get_uint32(&buf);
    iel->ulFreePublicMemory = vp_buffer_get_uint32(&buf);
    iel->ulTotalPrivateMemory = vp_buffer_get_uint32(&buf);
    iel->ulFreePrivateMemory = vp_buffer_get_uint32(&buf);
    {
      CK_VERSION *jel = &iel->hardwareVersion;

      jel->major = vp_buffer_get_byte(&buf);
      jel->minor = vp_buffer_get_byte(&buf);
    }
    {
      CK_VERSION *jel = &iel->firmwareVersion;

      jel->major = vp_buffer_get_byte(&buf);
      jel->minor = vp_buffer_get_byte(&buf);
    }
    vp_buffer_get_byte_arr(&buf, iel->utcTime, 16);
  }

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
CK_RV
C_WaitForSlotEvent
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
CK_RV
C_GetMechanismList
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050505);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, slotID);

  if (pMechanismList == NULL)
    vp_buffer_add_uint32(&buf, 0);
  else
    vp_buffer_add_uint32(&buf, *pulCount);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }


  {
    uint32_t count = vp_buffer_get_uint32(&buf);
    uint32_t i;

    if (pMechanismList == NULL)
      {
        *pulCount = count;
      }
    else if (count > *pulCount)
      {
        vp_buffer_uninit(&buf);
        return CKR_BUFFER_TOO_SMALL;
      }
    else
      {
        *pulCount = count;
        for (i = 0; i < count; i++)
          pMechanismList[i] = vp_buffer_get_uint32(&buf);
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

/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
CK_RV
C_GetMechanismInfo
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_InitToken initializes a token. */
CK_RV
C_InitToken
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050507);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_uint32(&buf, slotID);
  vp_buffer_add_byte_arr(&buf, pPin, ulPinLen);
  vp_buffer_add_byte_arr(&buf, pLabel, 32);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}

/* C_InitPIN initializes the normal user's PIN. */
CK_RV
C_InitPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050508);
  vp_buffer_add_space(&buf, 4);

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

/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV
C_SetPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_RV ret;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* XXX lookup session by hSession */

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050509);
  vp_buffer_add_space(&buf, 4);

  vp_buffer_add_byte_arr(&buf, pOldPin, ulOldLen);
  vp_buffer_add_byte_arr(&buf, pNewPin, ulNewLen);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_buffer_uninit(&buf);

  return ret;
}
