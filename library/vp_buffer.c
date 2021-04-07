/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

void
vp_buffer_init(VPBuffer *buf)
{
  memset(buf, 0, sizeof(*buf));
}

void
vp_buffer_uninit(VPBuffer *buf)
{
  free(buf->data);
  vp_buffer_init(buf);
}

void
vp_buffer_reset(VPBuffer *buf)
{
  buf->used = 0;
  buf->error = false;
}

unsigned char *
vp_buffer_ptr(VPBuffer *buf)
{
  if (buf->error)
    return NULL;

  return buf->data;
}

size_t
vp_buffer_len(VPBuffer *buf)
{
  if (buf->error)
    return 0;

  return buf->used;
}


unsigned char *
vp_buffer_add_space(VPBuffer *buf, size_t len)
{
  if (buf->used + len > buf->allocated)
    {
      size_t size;
      unsigned char *n;

      for (size = buf->allocated + 1024; buf->used + len > size; size += 1024)
        ;

      n = realloc(buf->data, size);
      if (n == NULL)
        {
          buf->error = true;
          return NULL;
        }
      buf->data = n;
      buf->allocated = size;
    }
  buf->used += len;

  return &buf->data[buf->used - len];
}

bool
vp_buffer_add_data(VPBuffer *buf, const unsigned char *data, size_t len)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, len);
  if (ucp == NULL)
    return false;

  memcpy(ucp, data, len);

  return true;
}

bool
vp_buffer_add_uint32(VPBuffer *buf, uint32_t v)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 4);
  if (ucp == NULL)
    return false;

  VP_PUT_UINT32(ucp, v);

  return true;
}

bool
vp_buffer_add_byte_arr(VPBuffer *buf, const void *data, size_t len)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 4 + len);
  if (ucp == NULL)
    return false;

  VP_PUT_UINT32(ucp, len);
  memcpy(ucp + 4, data, len);

  return true;
}
