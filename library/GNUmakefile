
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
	if test -x "$(RPCC)"; then \
	  $(RPCC) -c -o $@ $+; \
	else \
	  touch $@; \
	fi

libvpkcs11.so: $(filter %.c,$(SRCS))
	cc $(CFLAGS) $(LDFLAGS) -o $@ $+
