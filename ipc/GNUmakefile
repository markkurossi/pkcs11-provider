
RPCC := ../cmd/rpcc/rpcc
RPC_TYPES := ../library/pkcs11_types.rpct
RPCS := $(wildcard ../library/*.rpc)

all: rpc.go

rpc.go: ../cmd/rpcc/main.go $(RPC_TYPES) $(RPCS)
	if test -x "$(RPCC)"; then \
	  $(RPCC) -go -t $(RPC_TYPES) $(RPCS) > $@; \
	else \
	  touch $@; \
	fi
