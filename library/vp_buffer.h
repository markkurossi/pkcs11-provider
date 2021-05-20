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
  size_t offset;
  size_t used;
  CK_RV error;
};

typedef struct VPBufferStruct VPBuffer;

void vp_buffer_init(VPBuffer *buf);

void vp_buffer_uninit(VPBuffer *buf);

void vp_buffer_reset(VPBuffer *buf);

bool vp_buffer_error(VPBuffer *buf, CK_RV *error);

unsigned char *vp_buffer_ptr(VPBuffer *buf);

size_t vp_buffer_len(VPBuffer *buf);

unsigned char *vp_buffer_add_space(VPBuffer *buf, size_t len);

bool vp_buffer_add_data(VPBuffer *buf, const unsigned char *data, size_t len);

bool vp_buffer_add_bool(VPBuffer *buf, uint8_t v);

bool vp_buffer_add_uint32(VPBuffer *buf, uint32_t v);

bool vp_buffer_add_byte_arr(VPBuffer *buf, const void *data, size_t len);

unsigned char vp_buffer_get_byte(VPBuffer *buf);

uint32_t vp_buffer_get_uint32(VPBuffer *buf);

unsigned char *vp_buffer_get_data(VPBuffer *buf, size_t len);

bool vp_buffer_get_byte_arr(VPBuffer *buf, void *data, size_t data_count);

bool vp_buffer_get_uint32_arr(VPBuffer *buf, void *data, size_t data_count);

#endif /* not VP_BUFFER_H */
