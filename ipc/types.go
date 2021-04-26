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

// Flags that describe capabilities of a token.
const (
	CkfRNG                         CKFlags = 0x00000001
	CkfWriteProtected              CKFlags = 0x00000002
	CkfLoginRequired               CKFlags = 0x00000004
	CkfUserPinInitialized          CKFlags = 0x00000008
	CkfRestoreKeyNotNeeded         CKFlags = 0x00000020
	CkfClockOnToken                CKFlags = 0x00000040
	CkfProtectedAuthenticationPath CKFlags = 0x00000100
	CkfDualCryptoOperations        CKFlags = 0x00000200
	CkfTokenInitialized            CKFlags = 0x00000400
	CkfSecondaryAuthentication     CKFlags = 0x00000800
	CkfUserPINCountLow             CKFlags = 0x00010000
	CkfUserPINFinalTry             CKFlags = 0x00020000
	CkfUserPINLocked               CKFlags = 0x00040000
	CkfUserPINToBeChanged          CKFlags = 0x00080000
	CkfSOPINCountLow               CKFlags = 0x00100000
	CkfSOPINFinalTry               CKFlags = 0x00200000
	CkfSOPINLocked                 CKFlags = 0x00400000
	CkfSOPINToBeChanged            CKFlags = 0x00800000
	CkfErrorState                  CKFlags = 0x01000000
)
