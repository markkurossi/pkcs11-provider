/* This file is auto-generated from pkcs11_5_04_general_purpose.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/** Version: 3.0 */
/** Section: 5.4 General-purpose functions */

#define CK_PKCS11_FUNCTION_INFO(name) name,

static struct CK_FUNCTION_LIST_3_0 function_list =
  {
    {
      CRYPTOKI_VERSION_MAJOR,
      CRYPTOKI_VERSION_MINOR,
    },

#include "pkcs11f.h"

  };

static CK_C_INITIALIZE_ARGS init_args;

/* C_Initialize initializes the Cryptoki library. */
CK_RV
C_Initialize
(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced
                            */
)
{
  if (pInitArgs != NULL)
    memcpy(&init_args, pInitArgs, sizeof(CK_C_INITIALIZE_ARGS));

  return CKR_OK;
}

/* C_Finalize indicates that an application is done with the
 * Cryptoki library.
 */
CK_RV
C_Finalize
(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
  return CKR_OK;
}

/* C_GetInfo returns general information about Cryptoki. */
CK_RV
C_GetInfo
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GetFunctionList returns the function list. */
CK_RV
C_GetFunctionList
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list
                                            */
)
{
  if (ppFunctionList == NULL)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = (CK_FUNCTION_LIST_PTR) &function_list;

  return CKR_OK;
}

/* C_GetInterfaceList returns all the interfaces supported by the module*/
CK_RV
C_GetInterfaceList
(
  CK_INTERFACE_PTR  pInterfacesList,  /* returned interfaces */
  CK_ULONG_PTR      pulCount          /* number of interfaces returned */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}

/* C_GetInterface returns a specific interface from the module. */
CK_RV
C_GetInterface
(
  CK_UTF8CHAR_PTR       pInterfaceName, /* name of the interface */
  CK_VERSION_PTR        pVersion,       /* version of the interface */
  CK_INTERFACE_PTR_PTR  ppInterface,    /* returned interface */
  CK_FLAGS 		flags           /* flags controlling the semantics
                                         * of the interface */
)
{
  VP_FUNCTION_NOT_SUPPORTED;
}
