/*
 * Copyright (c) 2021-2023 Markku Rossi.
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
  buf->offset = 0;
  buf->used = 0;
  buf->error = CKR_OK;
}

bool
vp_buffer_error(VPBuffer *buf, CK_RV *error)
{
  /* Do not modify error if buffer does not have an error. */
  if (buf->error == CKR_OK)
    return false;

  *error = buf->error;

  return true;
}

unsigned char *
vp_buffer_ptr(VPBuffer *buf)
{
  if (buf->error != CKR_OK)
    return NULL;

  return buf->data + buf->offset;
}

size_t
vp_buffer_len(VPBuffer *buf)
{
  if (buf->error != CKR_OK)
    return 0;

  return buf->used - buf->offset;
}


unsigned char *
vp_buffer_add_space(VPBuffer *buf, size_t len)
{
  unsigned char *ucp;

  if (buf->used + len > buf->allocated)
    {
      size_t size;
      unsigned char *n;

      for (size = buf->allocated + 1024; buf->used + len > size; size += 1024)
        ;

      n = realloc(buf->data, size);
      if (n == NULL)
        {
          buf->error = CKR_HOST_MEMORY;
          return NULL;
        }
      buf->data = n;
      buf->allocated = size;
    }

  ucp = buf->data + buf->used;
  buf->used += len;

  memset(ucp, 0, len);

  return ucp;
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
vp_buffer_add_bool(VPBuffer *buf, uint8_t v)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 1);
  if (ucp == NULL)
    return false;

  ucp[0] = v;

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
vp_buffer_add_ulong(VPBuffer *buf, CK_ULONG v)
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

unsigned char
vp_buffer_get_byte(VPBuffer *buf)
{
  unsigned char *ucp;

  if (buf->offset + 1 > buf->used)
    {
      vp_log(LOG_ERR, "%s: CKR_DATA_LEN_RANGE", __FUNCTION__);
      buf->error = CKR_DATA_LEN_RANGE;
      return 0;
    }
  ucp = buf->data + buf->offset;
  buf->offset++;

  return ucp[0];
}

uint32_t
vp_buffer_get_uint32(VPBuffer *buf)
{
  unsigned char *ucp;

  if (buf->offset + 4 > buf->used)
    {
      vp_log(LOG_ERR, "%s: CKR_DATA_LEN_RANGE", __FUNCTION__);
      buf->error = CKR_DATA_LEN_RANGE;
      return 0;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  return VP_GET_UINT32(ucp);
}

unsigned char *
vp_buffer_get_data(VPBuffer *buf, size_t len)
{
  unsigned char *ucp;

  if (buf->offset + len > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      return NULL;
    }
  ucp = buf->data + buf->offset;
  buf->offset += len;

  return ucp;
}

bool
vp_buffer_get_byte_arr(VPBuffer *buf, void *data, size_t data_count)
{
  unsigned char *ucp;
  size_t len;

  if (buf->offset + 4 > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      return false;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  len = VP_GET_UINT32(ucp);
  ucp += 4;

  if (buf->offset + len > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      buf->offset = buf->used;
      return false;
    }
  if (len > data_count)
    {
      buf->error = CKR_BUFFER_TOO_SMALL;
      buf->offset += len;
      return false;
    }
  if (data != NULL)
    memcpy(data, ucp, len);

  buf->offset += len;

  return true;
}

bool
vp_buffer_get_uint32_arr(VPBuffer *buf, CK_ULONG *data, size_t data_count)
{
  unsigned char *ucp;
  size_t i, count;

  if (buf->offset + 4 > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      return false;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  count = VP_GET_UINT32(ucp);
  ucp += 4;

  if (buf->offset + count * 4 > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      buf->offset = buf->used;
      return false;
    }
  if (count > data_count)
    {
      buf->error = CKR_BUFFER_TOO_SMALL;
      buf->offset += count * 4;
      return false;
    }

  for (i = 0; i < count; i++)
    data[i] = vp_buffer_get_uint32(buf);

  return true;
}

bool
vp_buffer_get_ulong_arr(VPBuffer *buf, CK_ULONG *data, size_t data_count)
{
  unsigned char *ucp;
  size_t i, count;

  if (buf->offset + 4 > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      return false;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  count = VP_GET_UINT32(ucp);
  ucp += 4;

  if (buf->offset + count * 4 > buf->used)
    {
      buf->error = CKR_DATA_LEN_RANGE;
      buf->offset = buf->used;
      return false;
    }
  if (count > data_count)
    {
      buf->error = CKR_BUFFER_TOO_SMALL;
      buf->offset += count * 4;
      return false;
    }

  for (i = 0; i < count; i++)
    data[i] = vp_buffer_get_uint32(buf);

  return true;
}
