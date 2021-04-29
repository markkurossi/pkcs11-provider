/*
 * Copyright (C) 2020-2021 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_INCLUDES_H
#define VP_INCLUDES_H

#include <syslog.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

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

#include "vp_buffer.h"
#include "vp_getput.h"
#include "vp_ipc.h"

#define SOCKET_PATH "/tmp/vp.sock"

/****************** Implementation specific RPC functions *******************/

CK_RV C_ImplOpenSession(CK_ULONG ulProviderID, CK_SESSION_HANDLE hSession);
CK_RV C_ImplCloseSession(CK_SESSION_HANDLE hSession);


/*************************** Global library state ***************************/

extern CK_C_INITIALIZE_ARGS vp_init_args;
extern VPIPCConn *vp_global_conn;
extern void *vp_global_mutex;
extern CK_ULONG vp_provider_id;

VPIPCConn *vp_session(CK_SESSION_HANDLE id, CK_RV *ret);


/********************************* Logging **********************************/

void vp_log(int priority, char *msg, ...);

#define VP_FUNCTION_NOT_SUPPORTED			\
do {		       					\
  vp_log(LOG_ERR, "%s: not supported", __FUNCTION__);	\
  return CKR_FUNCTION_NOT_SUPPORTED;			\
} while (0)

#define VP_FUNCTION_ENTER vp_log(LOG_DEBUG, "%s: enter", __FUNCTION__)

#endif /* not VP_INCLUDES_H */
