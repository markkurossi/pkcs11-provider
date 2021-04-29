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

var mechanisms = map[ipc.CKMechanismType]ipc.CKMechanismInfo{
	ipc.CkmRSAPKCSKeyPairGen: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags:      ipc.CkfGenerateKeyPair,
	},
	ipc.CkmRSAPKCS: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags: ipc.CkfMessageEncrypt | ipc.CkfMessageDecrypt |
			ipc.CkfMessageSign | ipc.CkfMessageVerify | ipc.CkfEncrypt |
			ipc.CkfDecrypt | ipc.CkfSign | ipc.CkfVerify,
	},
}

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
	id      ipc.CKUlong
	parent  *Provider
	session *Session
}

// Initialize implements ipc.Provider.Initialize().
func (p *Provider) Initialize() (*ipc.InitializeResp, error) {
	return &ipc.InitializeResp{
		ProviderID: p.id,
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

// GetMechanismList implements the Provider.GetMechanismList().
func (p *Provider) GetMechanismList(req *ipc.GetMechanismListReq) (*ipc.GetMechanismListResp, error) {
	var result []ipc.CKMechanismType

	for k := range mechanisms {
		result = append(result, k)
	}

	return &ipc.GetMechanismListResp{
		MechanismList: result,
	}, nil
}

// GetMechanismInfo implements the Provider.GetMechanismInfo().
func (p *Provider) GetMechanismInfo(req *ipc.GetMechanismInfoReq) (*ipc.GetMechanismInfoResp, error) {
	if req.SlotID != 0 {
		return nil, ipc.ErrSlotIDInvalid
	}
	info, ok := mechanisms[req.Type]
	if !ok {
		return nil, ipc.ErrMechanismInvalid
	}
	return &ipc.GetMechanismInfoResp{
		Info: info,
	}, nil
}

// OpenSession implements the Provider.OpenSession().
func (p *Provider) OpenSession(req *ipc.OpenSessionReq) (*ipc.OpenSessionResp, error) {
	if req.SlotID != 0 {
		return nil, ipc.ErrSlotIDInvalid
	}
	session, err := NewSession()
	if err != nil {
		return nil, err
	}
	session.Flags = req.Flags

	return &ipc.OpenSessionResp{
		Session: session.ID,
	}, nil
}

// ImplOpenSession implements the Provider.ImplOpenSession().
func (p *Provider) ImplOpenSession(req *ipc.ImplOpenSessionReq) error {
	parent, err := LookupProvider(req.ProviderID)
	if err != nil {
		return err
	}
	p.parent = parent

	session, err := LookupSession(req.Session)
	if err != nil {
		return err
	}
	p.session = session
	return nil
}
