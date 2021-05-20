//
// byteorder_amd64.go
//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package pkcs11

import (
	"encoding/binary"
)

// HBO defines the host byte order.
var HBO = binary.LittleEndian
