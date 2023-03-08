AWS := aws-cloudhsm-pkcs11-examples
BINARIES := bin/aes_cbc bin/aes_gcm bin/aes_ecb \
	bin/digest bin/multi_part_digest \
	bin/find_objects

CFLAGS := -Wall -Wno-pointer-sign -I$(AWS)/src/common -I$(AWS)/include/pkcs11/v2.40

COMMON_SRCS := $(wildcard $(AWS)/src/common/*.c)

all: $(AWS) bin $(BINARIES)

aws-cloudhsm-pkcs11-examples:
	git clone https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples.git

bin:
	mkdir bin

clean:
	rm -f $(BINARIES)

bin/aes_cbc: $(AWS)/src/encrypt/aes_cbc.c $(AWS)/src/encrypt/aes.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/aes_gcm: $(AWS)/src/encrypt/aes_gcm.c $(AWS)/src/encrypt/aes.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/aes_ecb: $(AWS)/src/encrypt/aes_ecb.c $(AWS)/src/encrypt/aes.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/digest: $(AWS)/src/digest/digest.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/multi_part_digest: $(AWS)/src/digest/multi_part_digest.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/find_objects: $(AWS)/src/find_objects/find_objects.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

test:
	for b in $(BINARIES); do \
	  $$b --pin foo:bar --library ../library/libvpkcs11.so; \
	done
