/* This file is auto-generated from pkcs11_5_04_general_purpose.rpc by rpcc. */
/* -*- c -*-
 *
 * Copyright (c) 2020-2023 Markku Rossi.
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

CK_C_INITIALIZE_ARGS vp_init_args = {0};
VPIPCConn *vp_global_conn = NULL;
void *vp_global_mutex = NULL;
CK_ULONG vp_provider_id;

static CK_RV
mutex_create(void **ret)
{
  pthread_mutex_t *mutex;

  if (ret == NULL)
    return CKR_ARGUMENTS_BAD;

  mutex = calloc(1, sizeof(*mutex));
  if (mutex == NULL)
    return CKR_HOST_MEMORY;

  if (pthread_mutex_init(mutex, NULL) != 0)
    {
      free(mutex);
      return CKR_HOST_MEMORY;
    }

  *ret = mutex;

  return CKR_OK;
}

static CK_RV
mutex_destroy(void *ptr)
{
  if (ptr != NULL)
    {
      pthread_mutex_t *mutex = (pthread_mutex_t *) ptr;

      pthread_mutex_destroy(mutex);
      free(mutex);
    }

  return CKR_OK;
}

static CK_RV
mutex_lock(void *ptr)
{
  pthread_mutex_t *mutex = (pthread_mutex_t *) ptr;

  if (mutex == NULL)
    return CKR_ARGUMENTS_BAD;

  if (pthread_mutex_lock(mutex) != 0)
    return CKR_CANT_LOCK;

  return CKR_OK;
}

static CK_RV
mutex_unlock(void *ptr)
{
  pthread_mutex_t *mutex = (pthread_mutex_t *) ptr;

  if (mutex == NULL)
    return CKR_ARGUMENTS_BAD;

  if (pthread_mutex_unlock(mutex) != 0)
    return CKR_ARGUMENTS_BAD;

  return CKR_OK;
}

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
  CK_ULONG *pulProviderID = &vp_provider_id;

  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  memset(&vp_init_args, 0, sizeof(vp_init_args));

  if (pInitArgs != NULL)
    memcpy(&vp_init_args, pInitArgs, sizeof(vp_init_args));
  else
    vp_init_args.flags = CKF_OS_LOCKING_OK;

  if (vp_init_args.CreateMutex == NULL
      || vp_init_args.DestroyMutex == NULL
      || vp_init_args.LockMutex == NULL
      || vp_init_args.UnlockMutex == NULL)
    {
      if ((vp_init_args.flags & CKF_OS_LOCKING_OK) == 0)
        {
          vp_log(LOG_ERR, "%s: no mutex pointers and !CKF_OS_LOCKING_OK",
                 __FUNCTION__);
          return CKR_ARGUMENTS_BAD;
        }
      vp_init_args.CreateMutex = mutex_create;
      vp_init_args.DestroyMutex = mutex_destroy;
      vp_init_args.LockMutex = mutex_lock;
      vp_init_args.UnlockMutex = mutex_unlock;
    }

  ret = vp_init_args.CreateMutex(&vp_global_mutex);
  if (ret != CKR_OK)
    {
      C_Finalize(NULL);
      return ret;
    }

  vp_global_conn = vp_ipc_connect(SOCKET_PATH);
  if (vp_global_conn == NULL)
    {
      vp_log(LOG_ERR, "%s: failed to connect: '%s'", __FUNCTION__, SOCKET_PATH);
      C_Finalize(NULL);
      return CKR_DEVICE_REMOVED;
    }


  /* Use global session. */
  conn = vp_global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050401);
  vp_buffer_add_space(&buf, 4);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  *pulProviderID = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf, &ret))
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  vp_log(LOG_INFO, "ProviderID: %08lx", (unsigned long) vp_provider_id);


  vp_buffer_uninit(&buf);

  return ret;
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
  VP_FUNCTION_ENTER;

  if (vp_global_mutex != NULL)
    {
      vp_init_args.DestroyMutex(vp_global_mutex);
      vp_global_mutex = NULL;
    }

  vp_ipc_close(vp_global_conn);
  vp_global_conn = NULL;

  return CKR_OK;
}

/* C_GetInfo returns general information about Cryptoki. */
CK_RV
C_GetInfo
(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
  CK_RV ret = CKR_OK;
  VPBuffer buf;
  VPIPCConn *conn = NULL;

  VP_FUNCTION_ENTER;

  /* Use global session. */
  conn = vp_global_conn;

  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0xc0050403);
  vp_buffer_add_space(&buf, 4);

  ret = vp_ipc_tx(conn, &buf);
  if (ret != CKR_OK)
    {
      vp_buffer_uninit(&buf);
      return ret;
    }

  {
    CK_INFO *iel = pInfo;

    {
      CK_VERSION *jel = &iel->cryptokiVersion;

      jel->major = vp_buffer_get_byte(&buf);
      jel->minor = vp_buffer_get_byte(&buf);
    }
    vp_buffer_get_byte_arr(&buf, iel->manufacturerID, 32);
    iel->flags = vp_buffer_get_uint32(&buf);
    vp_buffer_get_byte_arr(&buf, iel->libraryDescription, 32);
    {
      CK_VERSION *jel = &iel->libraryVersion;

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

/* C_GetFunctionList returns the function list. */
CK_RV
C_GetFunctionList
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list
                                            */
)
{
  VP_FUNCTION_ENTER;

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
