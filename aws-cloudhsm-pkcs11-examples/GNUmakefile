AWS := aws-cloudhsm-pkcs11-examples
BINARIES := bin/aes_cbc

CFLAGS := -Wall -I$(AWS)/src/common -I$(AWS)/include/pkcs11/v2.40

COMMON_SRCS := $(wildcard $(AWS)/src/common/*.c)

all: $(AWS) bin $(BINARIES)

aws-cloudhsm-pkcs11-examples:
	git clone https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples.git

bin:
	mkdir bin

bin/aes_cbc: $(AWS)/src/encrypt/aes_cbc.c $(AWS)/src/encrypt/aes.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

test:
	for b in $(BINARIES); do \
	  $$b --pin foo:bar --library ../library/libvpkcs11.so; \
	done
