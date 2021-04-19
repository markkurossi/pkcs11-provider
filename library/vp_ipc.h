/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_IPC_H
#define VP_IPC_H

/*********************************** IPC ************************************/

struct VPIPCConnStruct
{
  int socket;
};

typedef struct VPIPCConnStruct VPIPCConn;

VPIPCConn *vp_ipc_connect(const char *path);

bool vp_ipc_read(VPIPCConn *conn, void *buf, size_t nbyte);

bool vp_ipc_write(VPIPCConn *conn, const void *buf, size_t nbyte);

bool vp_ipc_close(VPIPCConn *conn);

#endif /* not VP_IPC_H */
