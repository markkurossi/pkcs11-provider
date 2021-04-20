//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"

	"github.com/markkurossi/pkcs11-provider/ipc"
)

const (
	path = "/tmp/vp.sock"
)

var (
	bo = binary.BigEndian
)

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
	provider := &Provider{}

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
