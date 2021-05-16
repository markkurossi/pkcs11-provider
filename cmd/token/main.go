//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
	m         sync.Mutex
	bo        = binary.BigEndian
	providers = make(map[pkcs11.Ulong]*Provider)
	sessions  = make(map[pkcs11.SessionHandle]*Session)
)

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
	ID     pkcs11.SessionHandle
	Flags  pkcs11.Flags
	Digest hash.Hash
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

func main() {
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
		log.Printf("\u250C\u2500%s:\n", msgType.Name())

		var msg []byte
		if length > 0 {
			msg = make([]byte, length)
			_, err = conn.Read(msg)
			if err != nil {
				return err
			}
			if length > 32 {
				log.Printf("\u251c\u2500\u2500\u2500\u2500req: length=%d:\n%s",
					length, hex.Dump(msg))
			} else {
				log.Printf("\u251c\u2500\u2500\u2500\u2500req: %x\n", msg)
			}
		}

		ret, data := pkcs11.Dispatch(provider, msgType, msg)
		if len(data) > 32 {
			log.Printf("\u2514>%s: length=%d:\n%s",
				ret, len(data), hex.Dump(data))
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
