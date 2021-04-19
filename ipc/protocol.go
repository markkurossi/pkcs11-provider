//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package ipc

import (
	"fmt"
)

// Type specifies IPC protocol message type.
type Type uint32

func (t Type) String() string {
	return fmt.Sprintf("%d.%d-%d.%d.%d",
		t.Major(), t.Minor(), t.S0(), t.S1(), t.S2())
}

// Name returns the type's PKCS #11 function name.
func (t Type) Name() string {
	name, ok := msgTypeNames[t]
	if ok {
		return name
	}
	return t.String()
}

// NewType constructs an IPC message type from the components.
func NewType(vMajor, vMinor, s0, s1, s2 int) Type {
	return Type(uint32((vMajor-2)<<6|vMinor)<<24 |
		uint32(s0)<<16 | uint32(s1)<<8 | uint32(s2))
}

// Major returns the PKCS #11 major version number.
func (t Type) Major() int {
	return int(((t>>24)&0xff)>>6) + 2
}

// Minor returns the PKCS #11 minor version number.
func (t Type) Minor() int {
	return int((t >> 24) & 0x3f)
}

// S0 returns the PKCS #11 section number.
func (t Type) S0() int {
	return int(t>>16) & 0xff
}

// S1 returns the PKCS #11 subsection number.
func (t Type) S1() int {
	return int(t>>8) & 0xff
}

// S2 returns the PKCS #11 function number in its subsection.
func (t Type) S2() int {
	return int(t) & 0xff
}
