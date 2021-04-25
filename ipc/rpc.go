// This file is auto-generated by rpcc.
//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package ipc

import (
	"log"
)

// CKAttributeType defines basic protocol type CK_ATTRIBUTE_TYPE.
type CKAttributeType uint32

// CKBbool defines basic protocol type CK_BBOOL.
type CKBbool bool

// CKByte defines basic protocol type CK_BYTE.
type CKByte byte

// CKChar defines basic protocol type CK_CHAR.
type CKChar byte

// CKFlags defines basic protocol type CK_FLAGS.
type CKFlags uint32

// CKMechanismType defines basic protocol type CK_MECHANISM_TYPE.
type CKMechanismType uint32

// CKObjectHandle defines basic protocol type CK_OBJECT_HANDLE.
type CKObjectHandle uint32

// CKSessionHandle defines basic protocol type CK_SESSION_HANDLE.
type CKSessionHandle uint32

// CKSlotID defines basic protocol type CK_SLOT_ID.
type CKSlotID uint32

// CKSlotIDPtr defines basic protocol type CK_SLOT_ID_PTR.
type CKSlotIDPtr uint32

// CKUlong defines basic protocol type CK_ULONG.
type CKUlong uint32

// CKUlongPtr defines basic protocol type CK_ULONG_PTR.
type CKUlongPtr uint32

// CKUTF8Char defines basic protocol type CK_UTF8CHAR.
type CKUTF8Char byte

// CKVoidPtr defines basic protocol type CK_VOID_PTR.
type CKVoidPtr byte

// CKAttribute defines compound protocol type CK_ATTRIBUTE.
type CKAttribute struct {
	Type  CKAttributeType
	Value []CKVoidPtr
}

// CKInfo defines compound protocol type CK_INFO.
type CKInfo struct {
	CryptokiVersion    CKVersion
	ManufacturerID     [32]CKUTF8Char
	Flags              CKFlags
	LibraryDescription [32]CKUTF8Char
	LibraryVersion     CKVersion
}

// CKMechanismInfo defines compound protocol type CK_MECHANISM_INFO.
type CKMechanismInfo struct {
	MinKeySize CKUlong
	MaxKeySize CKUlong
	Flags      CKFlags
}

// CKSlotInfo defines compound protocol type CK_SLOT_INFO.
type CKSlotInfo struct {
	SlotDescription [64]CKUTF8Char
	ManufacturerID  [32]CKUTF8Char
	Flags           CKFlags
	HardwareVersion CKVersion
	FirmwareVersion CKVersion
}

// CKTokenInfo defines compound protocol type CK_TOKEN_INFO.
type CKTokenInfo struct {
	Label              [32]CKUTF8Char
	ManufacturerID     [32]CKUTF8Char
	Model              [16]CKUTF8Char
	SerialNumber       [16]CKChar
	Flags              CKFlags
	MaxSessionCount    CKUlong
	SessionCount       CKUlong
	MaxRwSessionCount  CKUlong
	RwSessionCount     CKUlong
	MaxPinLen          CKUlong
	MinPinLen          CKUlong
	TotalPublicMemory  CKUlong
	FreePublicMemory   CKUlong
	TotalPrivateMemory CKUlong
	FreePrivateMemory  CKUlong
	HardwareVersion    CKVersion
	FirmwareVersion    CKVersion
	UtcTime            [16]CKChar
}

// CKVersion defines compound protocol type CK_VERSION.
type CKVersion struct {
	Major CKByte
	Minor CKByte
}

// InitializeResp defines the result of C_Initialize.
type InitializeResp struct {
	NumSlots CKUlong
}

// GetInfoResp defines the result of C_GetInfo.
type GetInfoResp struct {
	Info CKInfo
}

// GetSlotListReq defines the arguments of C_GetSlotList.
type GetSlotListReq struct {
	TokenPresent CKBbool
	SlotListSize uint32
}

// GetSlotListResp defines the result of C_GetSlotList.
type GetSlotListResp struct {
	SlotList []CKSlotID
}

// GetSlotInfoReq defines the arguments of C_GetSlotInfo.
type GetSlotInfoReq struct {
	SlotID CKSlotID
}

// GetSlotInfoResp defines the result of C_GetSlotInfo.
type GetSlotInfoResp struct {
	Info CKSlotInfo
}

// InitTokenReq defines the arguments of C_InitToken.
type InitTokenReq struct {
	SlotID CKSlotID
	Pin    []CKUTF8Char
	Label  [32]CKUTF8Char
}

// InitPINReq defines the arguments of C_InitPIN.
type InitPINReq struct {
	Pin []CKUTF8Char
}

// SetPINReq defines the arguments of C_SetPIN.
type SetPINReq struct {
	OldPin []CKUTF8Char
	NewPin []CKUTF8Char
}

// DestroyObjectReq defines the arguments of C_DestroyObject.
type DestroyObjectReq struct {
	Object CKObjectHandle
}

// GetObjectSizeReq defines the arguments of C_GetObjectSize.
type GetObjectSizeReq struct {
	Object CKObjectHandle
}

// GetObjectSizeResp defines the result of C_GetObjectSize.
type GetObjectSizeResp struct {
	Size CKUlong
}

// Provider defines the PKCS #11 provider interface.
type Provider interface {
	Initialize() (*InitializeResp, error)
	GetInfo() (*GetInfoResp, error)
	GetSlotList(req *GetSlotListReq) (*GetSlotListResp, error)
	GetSlotInfo(req *GetSlotInfoReq) (*GetSlotInfoResp, error)
	InitToken(req *InitTokenReq) error
	InitPIN(req *InitPINReq) error
	SetPIN(req *SetPINReq) error
	DestroyObject(req *DestroyObjectReq) error
	GetObjectSize(req *GetObjectSizeReq) (*GetObjectSizeResp, error)
	FindObjectsFinal() error
}

// Base provides a dummy implementation of the Provider interface.
type Base struct{}

// Initialize implements the Provider.Initialize().
func (b *Base) Initialize() (*InitializeResp, error) {
	return nil, ErrFunctionNotSupported
}

// GetInfo implements the Provider.GetInfo().
func (b *Base) GetInfo() (*GetInfoResp, error) {
	return nil, ErrFunctionNotSupported
}

// GetSlotList implements the Provider.GetSlotList().
func (b *Base) GetSlotList(req *GetSlotListReq) (*GetSlotListResp, error) {
	return nil, ErrFunctionNotSupported
}

// GetSlotInfo implements the Provider.GetSlotInfo().
func (b *Base) GetSlotInfo(req *GetSlotInfoReq) (*GetSlotInfoResp, error) {
	return nil, ErrFunctionNotSupported
}

// InitToken implements the Provider.InitToken().
func (b *Base) InitToken(req *InitTokenReq) error {
	return ErrFunctionNotSupported
}

// InitPIN implements the Provider.InitPIN().
func (b *Base) InitPIN(req *InitPINReq) error {
	return ErrFunctionNotSupported
}

// SetPIN implements the Provider.SetPIN().
func (b *Base) SetPIN(req *SetPINReq) error {
	return ErrFunctionNotSupported
}

// DestroyObject implements the Provider.DestroyObject().
func (b *Base) DestroyObject(req *DestroyObjectReq) error {
	return ErrFunctionNotSupported
}

// GetObjectSize implements the Provider.GetObjectSize().
func (b *Base) GetObjectSize(req *GetObjectSizeReq) (*GetObjectSizeResp, error) {
	return nil, ErrFunctionNotSupported
}

// FindObjectsFinal implements the Provider.FindObjectsFinal().
func (b *Base) FindObjectsFinal() error {
	return ErrFunctionNotSupported
}

var msgTypeNames = map[Type]string{
	0xc0050401: "Initialize",
	0xc0050403: "GetInfo",
	0xc0050501: "GetSlotList",
	0xc0050502: "GetSlotInfo",
	0xc0050507: "InitToken",
	0xc0050508: "InitPIN",
	0xc0050509: "SetPIN",
	0xc0050703: "DestroyObject",
	0xc0050704: "GetObjectSize",
	0xc0050709: "FindObjectsFinal",
}

// Dispatch dispatches the message to provider and returns the message
// response.
func Dispatch(p Provider, msgType Type, req []byte) (CKRV, []byte) {
	resp, err := call(p, msgType, req)
	if err != nil {
		ckrv, ok := err.(CKRV)
		if ok {
			return ckrv, nil
		}
		log.Printf("dispatch error: %s", err)
		return ErrDataInvalid, nil
	}
	return ErrOk, resp
}

func call(p Provider, msgType Type, data []byte) ([]byte, error) {
	switch msgType {
	case 0xc0050401: // Initialize
		resp, err := p.Initialize()
		if err != nil {
			return nil, err
		}
		return Marshal(resp)

	case 0xc0050403: // GetInfo
		resp, err := p.GetInfo()
		if err != nil {
			return nil, err
		}
		return Marshal(resp)

	case 0xc0050501: // GetSlotList
		var req GetSlotListReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		resp, err := p.GetSlotList(&req)
		if err != nil {
			return nil, err
		}
		return Marshal(resp)

	case 0xc0050502: // GetSlotInfo
		var req GetSlotInfoReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		resp, err := p.GetSlotInfo(&req)
		if err != nil {
			return nil, err
		}
		return Marshal(resp)

	case 0xc0050507: // InitToken
		var req InitTokenReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, p.InitToken(&req)

	case 0xc0050508: // InitPIN
		var req InitPINReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, p.InitPIN(&req)

	case 0xc0050509: // SetPIN
		var req SetPINReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, p.SetPIN(&req)

	case 0xc0050703: // DestroyObject
		var req DestroyObjectReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, p.DestroyObject(&req)

	case 0xc0050704: // GetObjectSize
		var req GetObjectSizeReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}
		resp, err := p.GetObjectSize(&req)
		if err != nil {
			return nil, err
		}
		return Marshal(resp)

	case 0xc0050709: // FindObjectsFinal
		return nil, p.FindObjectsFinal()

	default:
		return nil, ErrFunctionNotSupported
	}
}
