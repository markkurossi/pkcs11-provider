/*
 * Copyright (C) 2020 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

void
vp_log(int priority, char *msg, ...)
{
  va_list ap;
  char buf[1024];

  va_start(ap, msg);
  vsnprintf(buf, sizeof(buf), msg, ap);
  va_end(ap);

  fprintf(stdout, "%s\n", buf);
}
