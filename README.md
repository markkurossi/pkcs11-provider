# pkcs11-provider

PKCS #11 provider library. This library implements the [PKCS #11
Cryptographic Token Interface Base Specification Version
3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
API and provides an RPC interface over Unix domain sockets to
communicate with the token implementation. The implementation has the
following components:

 - [library](library/) implements the PKCS #11 interface as C-shared
   library. The PKCS #11 functions are defined as `.rpc` files that
   are translated into `.c` files with the [RPC compiler](cmd/rpcc/).

 - [RPC Compiler](cmd/rpcc/) which is used to generated the PKCS #11
   stub functions from the RPC definitions. The RPC Compiler is
   implemented in [Go](https://golang.org/) programming language. You
   need the Go language only if you modify the `.rpc` files under
   library.

# TODO

 - [ ] RPC compiler
 - [ ] ASN.1 encode/decode
 - [ ] IPC over Unix domain sockets
 - [ ] crypto provider with Go
