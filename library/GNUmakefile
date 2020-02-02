
SRCS := $(wildcard *.c) $(wildcard *.h)

CFLAGS := -Iinclude -Wall -Werror -fPIC
LDFLAGS := -shared

all: libvpkcs11.so

libvpkcs11.so: $(filter %.c,$(SRCS))
	cc $(CFLAGS) $(LDFLAGS) -o $@ $+
