//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"bytes"
	"hash"
)

var (
	_ hash.Hash = &HashNone{}
)

// HashNone implements hash.Hash interface as identity operation.
type HashNone struct {
	buf bytes.Buffer
}

// Write implements io.Writer interface.
func (hash *HashNone) Write(p []byte) (int, error) {
	return hash.buf.Write(p)
}

// Sum implements the Hash.Sum().
func (hash *HashNone) Sum(b []byte) []byte {
	return hash.buf.Bytes()
}

// Reset implements the Hash.Reset().
func (hash *HashNone) Reset() {
	hash.buf.Reset()
}

// Size implements the hash.Size().
func (hash *HashNone) Size() int {
	return hash.buf.Len()
}

// BlockSize implements the hash.BlockSize().
func (hash *HashNone) BlockSize() int {
	return 1
}
