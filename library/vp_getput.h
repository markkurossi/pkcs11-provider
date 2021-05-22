/*
 * Copyright (c) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_GETPUT_H
#define VP_GETPUT_H

#define VP_GET_UINT32(buf)                              \
(  (((uint32_t) ((unsigned char *) (buf))[0]) << 24)    \
 | (((uint32_t) ((unsigned char *) (buf))[1]) << 16)    \
 | (((uint32_t) ((unsigned char *) (buf))[2]) << 8)     \
 |  ((uint32_t) ((unsigned char *) (buf))[3]))

#define VP_PUT_UINT32(buf, val)                         \
do {                                                    \
  unsigned char *__ucp = (unsigned char *) (buf);       \
  uint32_t __val = (uint32_t) (val);                    \
                                                        \
  __ucp[0] = (__val >> 24) & 0xff;                      \
  __ucp[1] = (__val >> 16) & 0xff;                      \
  __ucp[2] = (__val >> 8) & 0xff;                       \
  __ucp[3] = __val & 0xff;                              \
} while (0)

#endif /* not VP_GETPUT_H */
