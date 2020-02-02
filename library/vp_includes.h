/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_INCLUDES_H
#define VP_INCLUDES_H

#include <syslog.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

#define CK_PTR *
#define CK_BOOL bool
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

typedef unsigned long int CK_HANDLE;

#include <pkcs11.h>

void vp_log(int priority, char *msg, ...);

#define VP_FUNCTION_NOT_SUPPORTED			\
do {		       					\
  vp_log(LOG_ERR, "%s: not supported", __FUNCTION__);	\
  return CKR_FUNCTION_NOT_SUPPORTED;			\
} while (0)

#endif /* not VP_INCLUDES_H */
