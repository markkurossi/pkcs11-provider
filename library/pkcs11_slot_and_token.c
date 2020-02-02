/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_RV
C_GetSlotList
(
  CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
}
