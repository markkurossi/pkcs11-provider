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
		PulNumSlots: 1,
	}, nil
}

// GetSlotList implements the Provider.GetSlotList().
func (p *Provider) GetSlotList(req *ipc.GetSlotListReq) (*ipc.GetSlotListResp, error) {
	return &ipc.GetSlotListResp{
		PSlotList: []ipc.CKSlotID{0},
	}, nil
}
