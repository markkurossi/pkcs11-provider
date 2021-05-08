//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"encoding/binary"
	"hash"
	"log"
	"net"
	"os"
	"sync"

	"github.com/markkurossi/pkcs11-provider/ipc"
)

const (
	path = "/tmp/vp.sock"
)

var (
	m         sync.Mutex
	bo        = binary.BigEndian
	providers = make(map[ipc.CKUlong]*Provider)
	sessions  = make(map[ipc.CKSessionHandle]*Session)
)

// NewProvider creates a new provider instance.
func NewProvider() (*Provider, error) {
	var buf [4]byte

	m.Lock()
	defer m.Unlock()

	for {
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, ipc.ErrDeviceError
		}
		id := ipc.CKUlong(bo.Uint32(buf[:]))

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
func LookupProvider(id ipc.CKUlong) (*Provider, error) {
	m.Lock()
	defer m.Unlock()

	provider, ok := providers[id]
	if !ok {
		return nil, ipc.ErrArgumentsBad
	}

	return provider, nil
}

// Session implements a session with the token.
type Session struct {
	ID     ipc.CKSessionHandle
	Flags  ipc.CKFlags
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
			return nil, ipc.ErrDeviceError
		}
		id := ipc.CKSessionHandle(bo.Uint32(buf[:]))

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
func LookupSession(id ipc.CKSessionHandle) (*Session, error) {
	m.Lock()
	defer m.Unlock()

	session, ok := sessions[id]
	if !ok {
		return nil, ipc.ErrSessionHandleInvalid
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
			return err
		}

		msgType := ipc.Type(bo.Uint32(hdr[0:4]))
		length := bo.Uint32(hdr[4:8])
		log.Printf("msg=%s, length=%d\n", msgType.Name(), length)

		var msg []byte
		if length > 0 {
			msg = make([]byte, length)
			_, err = conn.Read(msg)
			if err != nil {
				return err
			}
		}

		ret, data := ipc.Dispatch(provider, msgType, msg)
		log.Printf("ret: %s, data=%d", ret, len(data))

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
