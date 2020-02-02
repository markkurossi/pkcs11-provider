/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

/* General-purpose */

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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
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
  VP_FUNCTION_NOT_SUPPORTED;
}
