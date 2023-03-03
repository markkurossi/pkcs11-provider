//
// Copyright (c) 2021-2023 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/markkurossi/pkcs11-provider/pkcs11"
)

const (
	path = "/tmp/vp.sock"
)

var (
	debug     bool
	m         sync.Mutex
	bo        = binary.BigEndian
	providers = make(map[pkcs11.Ulong]*Provider)
	sessions  = make(map[pkcs11.SessionHandle]*Session)
)

const (
	// FlagToken specifies that the object is stored on token storage
	// instead of session storage.
	FlagToken pkcs11.ObjectHandle = 0x1
)

func allocObjectHandle() (pkcs11.ObjectHandle, error) {
	var buf [8]byte

	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, pkcs11.ErrDeviceError
	}
	return pkcs11.ObjectHandle(bo.Uint64(buf[:])), nil
}

// NewProvider creates a new provider instance.
func NewProvider() (*Provider, error) {
	var buf [4]byte

	m.Lock()
	defer m.Unlock()

	for {
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, pkcs11.ErrDeviceError
		}
		id := pkcs11.Ulong(bo.Uint32(buf[:]))

		_, ok := providers[id]
		if ok {
			continue
		}
		provider := &Provider{
			id: id,
			storage: pkcs11.NewMemoryStorage(func() (
				pkcs11.ObjectHandle, error) {
				h, err := allocObjectHandle()
				if err != nil {
					return 0, err
				}
				h |= FlagToken
				return h, nil
			}),
		}
		providers[id] = provider
		return provider, nil
	}
}

// LookupProvider finds provider by its ID.
func LookupProvider(id pkcs11.Ulong) (*Provider, error) {
	m.Lock()
	defer m.Unlock()

	provider, ok := providers[id]
	if !ok {
		return nil, pkcs11.ErrArgumentsBad
	}

	return provider, nil
}

// Session implements a session with the token.
type Session struct {
	ID          pkcs11.SessionHandle
	Flags       pkcs11.Flags
	storage     pkcs11.Storage
	Digest      hash.Hash
	Encrypt     *EncDec
	Sign        *SignVerify
	Verify      *SignVerify
	FindObjects *FindObjects
}

// EncDec implements symmetric encrypt and decrypt operations.
type EncDec struct {
	Block     cipher.Block
	BlockMode cipher.BlockMode
	AEAD      cipher.AEAD
}

// SignVerify implements keypair sign and verify operations.
type SignVerify struct {
	Hash      crypto.Hash
	Digest    hash.Hash
	Mechanism pkcs11.Mechanism
	Key       interface{}
}

// NewSignVerify creates a sign/verify object from the mechanism.
func NewSignVerify(mechanism pkcs11.Mechanism) (*SignVerify, error) {
	var hashAlg crypto.Hash
	var digest hash.Hash

	switch mechanism.Mechanism {
	case pkcs11.CkmRSAPKCS:
		hashAlg = 0
		digest = new(HashNone)

	case pkcs11.CkmDSASHA224, pkcs11.CkmSHA224RSAPKCS,
		pkcs11.CkmSHA224RSAPKCSPSS, pkcs11.CkmECDSASHA224:
		hashAlg = crypto.SHA224
		digest = sha256.New224()

	case pkcs11.CkmDSASHA256, pkcs11.CkmSHA256RSAPKCS,
		pkcs11.CkmSHA256RSAPKCSPSS, pkcs11.CkmECDSASHA256:
		hashAlg = crypto.SHA256
		digest = sha256.New()

	case pkcs11.CkmDSASHA384, pkcs11.CkmSHA384RSAPKCS,
		pkcs11.CkmSHA384RSAPKCSPSS, pkcs11.CkmECDSASHA384:
		hashAlg = crypto.SHA384
		digest = sha512.New384()

	case pkcs11.CkmDSASHA512, pkcs11.CkmSHA512RSAPKCS,
		pkcs11.CkmSHA512RSAPKCSPSS, pkcs11.CkmECDSASHA512:
		hashAlg = crypto.SHA512
		digest = sha512.New()

	default:
		return nil, pkcs11.ErrMechanismInvalid
	}

	return &SignVerify{
		Hash:      hashAlg,
		Digest:    digest,
		Mechanism: mechanism,
	}, nil
}

// FindObjects implements find objects operation.
type FindObjects struct {
	Handles []pkcs11.ObjectHandle
}

// NewSession creates a new session instance.
func NewSession() (*Session, error) {
	var buf [4]byte

	m.Lock()
	defer m.Unlock()

	for {
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, pkcs11.ErrDeviceError
		}
		id := pkcs11.SessionHandle(bo.Uint32(buf[:]))

		_, ok := sessions[id]
		if ok {
			continue
		}
		session := &Session{
			ID: id,
			storage: pkcs11.NewMemoryStorage(func() (
				pkcs11.ObjectHandle, error) {
				h, err := allocObjectHandle()
				if err != nil {
					return 0, err
				}
				h &^= FlagToken
				return h, nil
			}),
		}
		sessions[id] = session
		return session, nil
	}
}

// LookupSession finds a session by its id.
func LookupSession(id pkcs11.SessionHandle) (*Session, error) {
	m.Lock()
	defer m.Unlock()

	session, ok := sessions[id]
	if !ok {
		return nil, pkcs11.ErrSessionHandleInvalid
	}

	return session, nil
}

// CloseSession closes the specified session.
func CloseSession(id pkcs11.SessionHandle) error {
	m.Lock()
	defer m.Unlock()

	_, ok := sessions[id]
	if !ok {
		return pkcs11.ErrSessionHandleInvalid
	}
	delete(sessions, id)

	return nil
}

func main() {
	flag.BoolVar(&debug, "D", false, "enable debug output")
	flag.Parse()
	log.SetFlags(0)

	log.Printf("Token starting\n")

	os.RemoveAll(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("failed to create listener: %s", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept failed: %s", err)
			continue
		}
		log.Printf("new connection")
		go func(conn net.Conn) {
			err := messageLoop(conn)
			if err != nil {
				log.Printf("messageLoop: %s", err)
			}
			conn.Close()
		}(conn)
	}
}

func messageLoop(conn net.Conn) error {
	var hdr [8]byte

	provider, err := NewProvider()
	if err != nil {
		return err
	}

	for {
		_, err := conn.Read(hdr[:])
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		msgType := pkcs11.Type(bo.Uint32(hdr[0:4]))
		length := bo.Uint32(hdr[4:8])
		log.Printf("\u250C\u2574%s:\n", msgType.Name())

		var msg []byte
		if length > 0 {
			msg = make([]byte, length)
			_, err = conn.Read(msg)
			if err != nil {
				return err
			}
			if length > 32 {
				if debug {
					log.Printf("\u251c\u2500\u2500\u2574req: length=%d:\n%s",
						length, hex.Dump(msg))
				} else {
					log.Printf("\u251c\u2500\u2500\u2574req: length=%d", length)
				}
			} else {
				log.Printf("\u251c\u2500\u2500\u2574req: %x\n", msg)
			}
		}

		ret, data := pkcs11.Dispatch(provider, msgType, msg)
		if len(data) > 32 {
			if debug {
				log.Printf("\u2514>%s: length=%d:\n%s",
					ret, len(data), hex.Dump(data))
			} else {
				log.Printf("\u2514>%s: length=%d\n", ret, len(data))
			}
		} else if len(data) > 0 {
			log.Printf("\u2514>%s: %x\n", ret, data)
		} else {
			log.Printf("\u2514>%s\n", ret)
		}

		bo.PutUint32(hdr[0:4], uint32(ret))
		bo.PutUint32(hdr[4:8], uint32(len(data)))

		_, err = conn.Write(hdr[:])
		if err != nil {
			return err
		}
		if len(data) > 0 {
			_, err = conn.Write(data)
			if err != nil {
				return err
			}
		}
	}
}
