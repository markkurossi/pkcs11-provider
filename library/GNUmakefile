
RPCC := ../cmd/rpcc/rpcc

RPCS := $(wildcard *.rpc)
RPC_SRCS := $(patsubst %.rpc,%.c,$(RPCS))
SRCS := $(RPC_SRCS) $(wildcard vp_*.c) $(wildcard *.h)

CFLAGS := -Iinclude -Wall -Werror -fPIC
LDFLAGS := -shared

all: libvpkcs11.so

clean:
	$(RM) libvpkcs11.so

maintainer-clean:
	$(RM) $(RPC_SRCS)

%.c : %.rpc
	$(RPCC) -c -o $@ $+

libvpkcs11.so: $(filter %.c,$(SRCS))
	cc $(CFLAGS) $(LDFLAGS) -o $@ $+
