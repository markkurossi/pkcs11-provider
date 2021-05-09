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
   implemented in [Go](https://golang.org/) programming language. You
   need the Go environment only if you modify the `.rpc` files under
   library.

 - [Software Token](cmd/token/) implementing PKCS #11 operations. The
   token is implemented in Go and (will) support all modern PKCS #11
   cryptographic operations.

# TODO

 - [ ] RPC compiler (ugly but it works):
   - [ ] Cleanup field input/output handling and types
   - [ ] Remove old unused input/output code
 - [X] IPC over Unix domain sockets
 - [ ] Crypto provider with Go
   - [ ] Message sign
   - [ ] Message digest
   - [ ] Random numbers
   - [ ] and others...
