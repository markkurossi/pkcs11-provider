/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

VPIPCConn *
vp_ipc_connect(const char *path)
{
  VPIPCConn *conn;
  struct sockaddr_un addr;

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

bool
vp_ipc_read(VPIPCConn *conn, void *buf, size_t nbyte)
{
  unsigned char *ucp = (unsigned char *) buf;
  ssize_t got;

  while (nbyte > 0)
    {
      got = read(conn->socket, ucp, nbyte);
      if (got == -1)
        return false;

      ucp += got;
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
      if (wrote == -1)
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
