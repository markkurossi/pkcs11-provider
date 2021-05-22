/*
 * Copyright (c) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

VPIPCConn *
vp_ipc_connect(const char *path)
{
  VPIPCConn *conn;
  struct sockaddr_un addr;

  if (strlen(path) >= sizeof(addr.sun_path))
    {
      vp_log(LOG_ERR, "IPC: socket path too long");
      return NULL;
    }

  conn = calloc(1, sizeof(*conn));
  if (conn == NULL)
    return NULL;

  conn->socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (conn->socket == -1)
    {
      vp_log(LOG_ERR, "IPC: socket failed: %s", strerror(errno));
      goto error;
    }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (connect(conn->socket, (struct sockaddr *) &addr, sizeof(addr)) == -1)
    {
      vp_log(LOG_ERR, "IPC: connect failed: %s", strerror(errno));
      goto error;
    }

  return conn;


  /* Error handling. */

 error:
  vp_ipc_close(conn);
  return NULL;
}

CK_RV
vp_ipc_tx(VPIPCConn *conn, VPBuffer *buf)
{
  unsigned char *ucp;
  CK_RV ret;
  uint32_t len;

  ucp = vp_buffer_ptr(buf);
  if (ucp == NULL)
    return CKR_HOST_MEMORY;

  len = vp_buffer_len(buf);
  VP_PUT_UINT32(ucp + 4, len - 8);

  if (!vp_ipc_write(conn, ucp, len))
    return CKR_DEVICE_ERROR;

  vp_buffer_reset(buf);

  ucp = vp_buffer_add_space(buf, 8);
  if (ucp == NULL)
    return CKR_HOST_MEMORY;

  if (!vp_ipc_read(conn, ucp, 8))
    return CKR_DEVICE_ERROR;

  ret = VP_GET_UINT32(ucp);
  if (ret != CKR_OK)
    return ret;

  len = VP_GET_UINT32(ucp + 4);
  if (len > 0xffff)
    {
      vp_ipc_discard(conn, len);
      return CKR_DEVICE_ERROR;
    }

  vp_buffer_reset(buf);

  ucp = vp_buffer_add_space(buf, len);
  if (ucp == NULL)
    return CKR_HOST_MEMORY;

  if (!vp_ipc_read(conn, ucp, len))
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}

bool
vp_ipc_read(VPIPCConn *conn, void *buf, size_t nbyte)
{
  unsigned char *ucp = (unsigned char *) buf;
  ssize_t got;

  while (nbyte > 0)
    {
      got = read(conn->socket, ucp, nbyte);
      if (got <= 0)
        return false;

      ucp += got;
      nbyte -= got;
    }

  return true;
}

bool
vp_ipc_discard(VPIPCConn *conn, size_t nbyte)
{
  unsigned char ucp[4096];
  ssize_t got;

  while (nbyte > 0)
    {
      size_t to_read;

      to_read = nbyte;
      if (to_read > sizeof(ucp))
        to_read = sizeof(ucp);

      got = read(conn->socket, ucp, to_read);
      if (got <= 0)
        return false;

      nbyte -= got;
    }

  return true;
}

bool
vp_ipc_write(VPIPCConn *conn, const void *buf, size_t nbyte)
{
  unsigned char *ucp = (unsigned char *) buf;
  ssize_t wrote;

  while (nbyte > 0)
    {
      wrote = write(conn->socket, ucp, nbyte);
      if (wrote <= 0)
        return false;

      ucp += wrote;
      nbyte -= wrote;
    }

  return true;
}

bool
vp_ipc_close(VPIPCConn *conn)
{
  int ret = 0;

  if (conn == NULL)
    return true;

  if (conn->socket >= 0)
    ret = close(conn->socket);

  free(conn);

  if (ret == -1)
    return false;

  return true;
}
