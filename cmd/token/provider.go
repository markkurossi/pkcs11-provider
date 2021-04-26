//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"log"
	"regexp"
	"runtime"
	"strconv"

	"github.com/markkurossi/pkcs11-provider/ipc"
)

var (
	reVersion = regexp.MustCompilePOSIX(`^[[:^digit:]]*([[:digit:]]+)\.([[:digit:]]+)`)

	fwVersion = ipc.CKVersion{
		Major: 0,
		Minor: 1,
	}
)

func goVersion() ipc.CKVersion {
	v := runtime.Version()
	log.Printf("runtime.Version: %s", v)
	m := reVersion.FindStringSubmatch(v)
	if m != nil {
		major, _ := strconv.ParseUint(m[1], 10, 8)
		minor, _ := strconv.ParseUint(m[2], 10, 8)
		return ipc.CKVersion{
			Major: ipc.CKByte(major),
			Minor: ipc.CKByte(minor),
		}
	}
	return ipc.CKVersion{}
}

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
			Flags:           ipc.CkfTokenPresent,
			HardwareVersion: goVersion(),
			FirmwareVersion: fwVersion,
		},
	}
	copy(result.Info.SlotDescription[:], []ipc.CKUTF8Char("Go crypto library"))
	copy(result.Info.ManufacturerID[:], []ipc.CKUTF8Char("mtr@iki.fi"))
	return result, nil
}

// GetTokenInfo implements the Provider.GetTokenInfo().
func (p *Provider) GetTokenInfo(req *ipc.GetTokenInfoReq) (*ipc.GetTokenInfoResp, error) {
	if req.SlotID != 0 {
		return nil, ipc.ErrSlotIDInvalid
	}

	result := &ipc.GetTokenInfoResp{
		Info: ipc.CKTokenInfo{
			Flags:           ipc.CkfRNG | ipc.CkfClockOnToken,
			HardwareVersion: goVersion(),
			FirmwareVersion: fwVersion,
		},
	}
	copy(result.Info.ManufacturerID[:], []ipc.CKUTF8Char("www.golang.org"))
	copy(result.Info.Model[:], []ipc.CKUTF8Char("Software"))
	return result, nil
}
