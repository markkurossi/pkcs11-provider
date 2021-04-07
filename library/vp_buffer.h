/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_BUFFER_H
#define VP_BUFFER_H

struct VPBufferStruct
{
  unsigned char *data;
  size_t allocated;
  size_t used;
  bool error;
};

typedef struct VPBufferStruct VPBuffer;

void vp_buffer_init(VPBuffer *buf);

void vp_buffer_uninit(VPBuffer *buf);

void vp_buffer_reset(VPBuffer *buf);

unsigned char *vp_buffer_ptr(VPBuffer *buf);

size_t vp_buffer_len(VPBuffer *buf);

unsigned char *vp_buffer_add_space(VPBuffer *buf, size_t len);

bool vp_buffer_add_data(VPBuffer *buf, const unsigned char *data, size_t len);

bool vp_buffer_add_uint32(VPBuffer *buf, uint32_t v);

bool vp_buffer_add_byte_arr(VPBuffer *buf, const void *data, size_t len);

#endif /* not VP_BUFFER_H */