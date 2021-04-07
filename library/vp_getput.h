/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#ifndef VP_GETPUT_H
#define VP_GETPUT_H

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
