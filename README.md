# PKCS #11 Provider

This project implements the [PKCS #11 Cryptographic Token Interface
Base Specification Version
3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
API and provides an RPC interface over Unix domain sockets to
communicate with the token implementation. The implementation has the
following components:

 - [library](library/) implements the PKCS #11 interface as a shared
   library. The PKCS #11 functions are defined in `.rpc` files and
   they are translated into `.c` files with the [RPC
   compiler](cmd/rpcc/).

 - [RPC Compiler](cmd/rpcc/) which is used to generated the PKCS #11
   stub functions from the RPC definitions. The RPC Compiler is
   implemented in [Go](https://golang.org/) programming language.

 - [Software Token](cmd/token/) implementing PKCS #11 operations. The
   token is implemented in Go and (will) support all modern PKCS #11
   cryptographic operations.

 - [Java PKCS #11 Test](java/) to test the PKCS #11 interface from
   Java.

# Example Usage

Start token:

```sh
$ cd cmd/token
$ ./token
```

Run [pkcs11-testing](https://github.com/markkurossi/pkcs11-testing)
test program:

```sh
$ cd ~/work/pkcs11-testing
$ ./pkcs11-testing --module ~/go/src/github.com/markkurossi/pkcs11-provider/library/libvpkcs11.so --slot 0 --pin 1111 --test-all
```

# TODO

 - [ ] Framework:
   - [ ] Launch token from `libvpkcs11.so`
   - [ ] Non-volatile token storage
   - [ ] Token configuration file
   - [ ] Test compatibility with Firefox
   - [ ] Test compatibility with [aws-cloudhsm-pkcs11-examples](https://github.com/aws-samples/aws-cloudhsm-pkcs11-examples)
 - [ ] Crypto provider with Go:
   - [ ] Object search and enumeration
   - [ ] Encryption and decryption
   - [ ] Multi-part message digest
   - [ ] Ed25519 public key algorithm
   - [ ] Message sign and verify
   - [ ] Dual function
   - [ ] Symmetric key generation
 - [X] RPC compiler (ugly but it works):
   - [ ] Cleanup field input/output handling and types
   - [ ] Remove old unused input/output code

# Documentation

 - [PKCS #11 Cryptographic Token Interface
Base Specification Version
3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
 - [Cryptographic Token Interface
   Standard](https://www.cryptsoft.com/pkcs11doc/v230/)
