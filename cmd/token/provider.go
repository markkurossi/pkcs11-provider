//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"github.com/markkurossi/pkcs11-provider/ipc"
)

// Provider implements ipc.Provider interface.
type Provider struct {
	ipc.Base
}

// Initialize implements ipc.Provider.Initialize().
func (p *Provider) Initialize() (*ipc.InitializeResp, error) {
	return &ipc.InitializeResp{
		NumSlots: 1,
	}, nil
}

// GetSlotList implements the Provider.GetSlotList().
func (p *Provider) GetSlotList(req *ipc.GetSlotListReq) (*ipc.GetSlotListResp, error) {
	return &ipc.GetSlotListResp{
		SlotList: []ipc.CKSlotID{0},
	}, nil
}

// GetSlotInfo implements the Provider.GetSlotInfo().
func (p *Provider) GetSlotInfo(req *ipc.GetSlotInfoReq) (*ipc.GetSlotInfoResp, error) {
	if req.SlotID != 0 {
		return nil, ipc.ErrSlotIDInvalid
	}

	result := &ipc.GetSlotInfoResp{
		Info: ipc.CKSlotInfo{
			Flags: ipc.CkfTokenPresent,
			FirmwareVersion: ipc.CKVersion{
				Major: 0,
				Minor: 1,
			},
		},
	}
	copy(result.Info.SlotDescription[:], []ipc.CKUTF8Char("Go crypto library"))
	copy(result.Info.ManufacturerID[:], []ipc.CKUTF8Char("mtr@iki.fi"))
	return result, nil
}
