//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package ipc

// Flags that describe capabilities of a slot.
const (
	CkfTokenPresent    CKFlags = 0x00000001
	CkfRemovableDevice CKFlags = 0x00000002
	CkfHWSlot          CKFlags = 0x00000004
)
