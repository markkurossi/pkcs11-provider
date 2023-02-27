/*
 * Copyright (c) 2020-2023 Markku Rossi.
 *
 * All rights reserved.
 */

#include "vp_includes.h"

void
vp_log(int priority, char *msg, ...)
{
  va_list ap;
  char buf[1024];

  if (priority > LOG_INFO)
    return;

  va_start(ap, msg);
  vsnprintf(buf, sizeof(buf), msg, ap);
  va_end(ap);

  fprintf(stdout, "%s\n", buf);
}
