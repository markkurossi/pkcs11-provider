//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"log"
	"regexp"
	"runtime"
	"strconv"
	"sync"

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
	m        sync.Mutex
	sessions map[ipc.CKSessionHandle]*Session
}

func (p *Provider) newSession() (*Session, error) {
	var buf [4]byte

	p.m.Lock()
	defer p.m.Unlock()

	for {
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, ipc.ErrDeviceError
		}
		id := ipc.CKSessionHandle(bo.Uint32(buf[:]))

		session, ok := p.sessions[id]
		if ok {
			continue
		}
		session = &Session{
			ID: id,
		}
		p.sessions[id] = session
		return session, nil
	}
}

// Session implements a session with the token.
type Session struct {
	ID    ipc.CKSessionHandle
	Flags ipc.CKFlags
}

// Initialize implements ipc.Provider.Initialize().
func (p *Provider) Initialize() (*ipc.InitializeResp, error) {
	p.sessions = make(map[ipc.CKSessionHandle]*Session)

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
	session, err := p.newSession()
	if err != nil {
		return nil, err
	}
	session.Flags = req.Flags

	return &ipc.OpenSessionResp{
		Session: session.ID,
	}, nil
}
