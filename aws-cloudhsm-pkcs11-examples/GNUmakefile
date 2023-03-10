AWS := aws-cloudhsm-pkcs11-examples

TESTS := bin/aes_cbc bin/aes_gcm bin/aes_ecb \
	bin/digest bin/multi_part_digest \
	bin/find_objects \
	bin/aes_generate bin/ec_generate bin/rsa_generate \
	bin/generate_random \
	bin/mechanism_info \
	bin/login_state bin/session_keys \
	bin/sign bin/multi_part_sign

BINARIES := $(TESTS) bin/attributes_cmd bin/destroy_cmd

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

bin/aes_generate: $(AWS)/src/generate/aes_generate.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/ec_generate: $(AWS)/src/generate/ec_generate.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/rsa_generate: $(AWS)/src/generate/rsa_generate.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/generate_random: $(AWS)/src/generate_random/generate_random.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/mechanism_info: $(AWS)/src/mechanism_info/mechanism_info.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/login_state: $(AWS)/src/session/login_state.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/session_keys: $(AWS)/src/session/session_keys.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/sign: $(AWS)/src/sign/rsa_sign.c $(AWS)/src/sign/ec_sign.c $(AWS)/src/sign/common.c $(AWS)/src/sign/sign.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/multi_part_sign: $(AWS)/src/sign/rsa_sign.c $(AWS)/src/sign/ec_sign.c $(AWS)/src/sign/common.c $(AWS)/src/sign/multi_part_sign.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/attributes_cmd: $(AWS)/src/attributes/attributes_cmd.c $(AWS)/src/attributes/attributes.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

bin/destroy_cmd: $(AWS)/src/destroy/destroy_cmd.c $(AWS)/src/destroy/destroy.c
	cc $(CFLAGS) -o $@ $+ $(COMMON_SRCS)

test:
	for b in $(TESTS); do \
	  $$b --pin foo:bar --library ../library/libvpkcs11.so; \
	done
