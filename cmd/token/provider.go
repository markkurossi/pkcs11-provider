//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strconv"

	"github.com/markkurossi/pkcs11-provider/pkcs11"
)

var (
	reVersion = regexp.MustCompilePOSIX(`^[[:^digit:]]*([[:digit:]]+)\.([[:digit:]]+)`)

	fwVersion = pkcs11.Version{
		Major: 0,
		Minor: 1,
	}
)

var mechanisms = map[pkcs11.MechanismType]pkcs11.MechanismInfo{
	pkcs11.CkmRSAPKCSKeyPairGen: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags:      pkcs11.CkfGenerateKeyPair,
	},
	pkcs11.CkmRSAPKCS: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA256RSAPKCS: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA512RSAPKCS: {
		MinKeySize: 2048,
		MaxKeySize: 8192,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA256: {
		Flags: pkcs11.CkfDigest,
	},
	pkcs11.CkmSHA384: {
		Flags: pkcs11.CkfDigest,
	},
	pkcs11.CkmSHA512: {
		Flags: pkcs11.CkfDigest,
	},
}

func goVersion() pkcs11.Version {
	v := runtime.Version()
	log.Printf("runtime.Version: %s", v)
	m := reVersion.FindStringSubmatch(v)
	if m != nil {
		major, _ := strconv.ParseUint(m[1], 10, 8)
		minor, _ := strconv.ParseUint(m[2], 10, 8)
		return pkcs11.Version{
			Major: pkcs11.Byte(major),
			Minor: pkcs11.Byte(minor),
		}
	}
	return pkcs11.Version{}
}

// Provider implements pkcs11.Provider interface.
type Provider struct {
	pkcs11.Base
	id      pkcs11.Ulong
	parent  *Provider
	session *Session
}

// Initialize implements pkcs11.Provider.Initialize().
func (p *Provider) Initialize() (*pkcs11.InitializeResp, error) {
	return &pkcs11.InitializeResp{
		ProviderID: p.id,
	}, nil
}

// GetSlotList implements the Provider.GetSlotList().
func (p *Provider) GetSlotList(req *pkcs11.GetSlotListReq) (*pkcs11.GetSlotListResp, error) {
	return &pkcs11.GetSlotListResp{
		SlotListLen: 1,
		SlotList:    []pkcs11.SlotID{0},
	}, nil
}

// GetSlotInfo implements the Provider.GetSlotInfo().
func (p *Provider) GetSlotInfo(req *pkcs11.GetSlotInfoReq) (*pkcs11.GetSlotInfoResp, error) {
	if req.SlotID != 0 {
		return nil, pkcs11.ErrSlotIDInvalid
	}

	result := &pkcs11.GetSlotInfoResp{
		Info: pkcs11.SlotInfo{
			Flags:           pkcs11.CkfTokenPresent,
			HardwareVersion: goVersion(),
			FirmwareVersion: fwVersion,
		},
	}
	copy(result.Info.SlotDescription[:], []pkcs11.UTF8Char("Go crypto library"))
	copy(result.Info.ManufacturerID[:], []pkcs11.UTF8Char("mtr@iki.fi"))
	return result, nil
}

// GetTokenInfo implements the Provider.GetTokenInfo().
func (p *Provider) GetTokenInfo(req *pkcs11.GetTokenInfoReq) (*pkcs11.GetTokenInfoResp, error) {
	if req.SlotID != 0 {
		return nil, pkcs11.ErrSlotIDInvalid
	}

	result := &pkcs11.GetTokenInfoResp{
		Info: pkcs11.TokenInfo{
			Flags:           pkcs11.CkfRNG | pkcs11.CkfClockOnToken,
			HardwareVersion: goVersion(),
			FirmwareVersion: fwVersion,
		},
	}
	copy(result.Info.ManufacturerID[:], []pkcs11.UTF8Char("www.golang.org"))
	copy(result.Info.Model[:], []pkcs11.UTF8Char("Software"))
	return result, nil
}

// GetMechanismList implements the Provider.GetMechanismList().
func (p *Provider) GetMechanismList(req *pkcs11.GetMechanismListReq) (*pkcs11.GetMechanismListResp, error) {
	var result []pkcs11.MechanismType

	for k := range mechanisms {
		result = append(result, k)
	}

	return &pkcs11.GetMechanismListResp{
		MechanismListLen: len(result),
		MechanismList:    result,
	}, nil
}

// GetMechanismInfo implements the Provider.GetMechanismInfo().
func (p *Provider) GetMechanismInfo(req *pkcs11.GetMechanismInfoReq) (*pkcs11.GetMechanismInfoResp, error) {
	if req.SlotID != 0 {
		return nil, pkcs11.ErrSlotIDInvalid
	}
	info, ok := mechanisms[req.Type]
	if !ok {
		return nil, pkcs11.ErrMechanismInvalid
	}
	return &pkcs11.GetMechanismInfoResp{
		Info: info,
	}, nil
}

// OpenSession implements the Provider.OpenSession().
func (p *Provider) OpenSession(req *pkcs11.OpenSessionReq) (*pkcs11.OpenSessionResp, error) {
	if req.SlotID != 0 {
		return nil, pkcs11.ErrSlotIDInvalid
	}
	session, err := NewSession()
	if err != nil {
		return nil, err
	}
	session.Flags = req.Flags

	return &pkcs11.OpenSessionResp{
		Session: session.ID,
	}, nil
}

// ImplOpenSession implements the Provider.ImplOpenSession().
func (p *Provider) ImplOpenSession(req *pkcs11.ImplOpenSessionReq) error {
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

// Login implements the Provider.Login().
func (p *Provider) Login(req *pkcs11.LoginReq) error {
	log.Printf("Login: UserType=%v, Pin=%v", req.UserType, string(req.Pin))
	return nil
}

// CreateObject implements the Provider.CreateObject().
func (p *Provider) CreateObject(req *pkcs11.CreateObjectReq) (*pkcs11.CreateObjectResp, error) {
	for idx, attr := range req.Template {
		fmt.Printf("%d:\t%s\n", idx, attr.Type)
		if len(attr.Value) > 0 {
			fmt.Printf("%s", hex.Dump(attr.Value))
		}
	}

	return nil, pkcs11.ErrFunctionNotSupported
}

// DigestInit implements the Provider.DigestInit().
func (p *Provider) DigestInit(req *pkcs11.DigestInitReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.Digest != nil {
		return pkcs11.ErrOperationActive
	}

	switch req.Mechanism.Mechanism {
	case pkcs11.CkmSHA256:
		p.session.Digest = sha256.New()
		return nil

	case pkcs11.CkmSHA512:
		p.session.Digest = sha512.New()
		return nil

	default:
		log.Printf("DigestInit: Mechanism=%x", req.Mechanism.Mechanism)
		return pkcs11.ErrMechanismInvalid
	}
}

// Digest implements the Provider.Digest().
func (p *Provider) Digest(req *pkcs11.DigestReq) (*pkcs11.DigestResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	hash := p.session.Digest
	if hash == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}
	resp := &pkcs11.DigestResp{
		DigestLen: hash.Size(),
	}
	if req.DigestSize == 0 {
		return resp, nil
	}
	hash.Write(req.Data)
	resp.Digest = hash.Sum(nil)
	p.session.Digest = nil

	return resp, nil
}

// DigestUpdate implements the Provider.DigestUpdate().
func (p *Provider) DigestUpdate(req *pkcs11.DigestUpdateReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	hash := p.session.Digest
	if hash == nil {
		return pkcs11.ErrOperationNotInitialized
	}
	hash.Write(req.Part)

	return nil
}

// DigestFinal implements the Provider.DigestFinal().
func (p *Provider) DigestFinal(req *pkcs11.DigestFinalReq) (*pkcs11.DigestFinalResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	hash := p.session.Digest
	if hash == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}
	resp := &pkcs11.DigestFinalResp{
		DigestLen: hash.Size(),
	}
	if req.DigestSize == 0 {
		return resp, nil
	}
	resp.Digest = hash.Sum(nil)
	p.session.Digest = nil

	return resp, nil
}

// GenerateKeyPair implements the Provider.GenerateKeyPair().
func (p *Provider) GenerateKeyPair(req *pkcs11.GenerateKeyPairReq) (*pkcs11.GenerateKeyPairResp, error) {
	log.Printf("GenerateKeyPair: %s", req.Mechanism)
	log.Printf("PublicKeyTemplate:")
	for idx, attr := range req.PublicKeyTemplate {
		log.Printf(" - %d: %s\n", idx, attr.Type)
		if len(attr.Value) > 0 {
			log.Printf("%s", hex.Dump(attr.Value))
		}
	}
	log.Printf("PrivateKeyTemplate:")
	for idx, attr := range req.PrivateKeyTemplate {
		log.Printf(" - %d: %s\n", idx, attr.Type)
		if len(attr.Value) > 0 {
			log.Printf("%s", hex.Dump(attr.Value))
		}
	}

	switch req.Mechanism.Mechanism {
	case pkcs11.CkmRSAPKCSKeyPairGen, pkcs11.CkmRSAX931KeyPairGen:

	default:
		return nil, pkcs11.ErrMechanismInvalid
	}

	return nil, pkcs11.ErrFunctionNotSupported
}

// SeedRandom implements the Provider.SeedRandom().
func (p *Provider) SeedRandom(req *pkcs11.SeedRandomReq) error {
	return pkcs11.ErrRandomSeedNotSupported
}

// GenerateRandom implements the Provider.GenerateRandom().
func (p *Provider) GenerateRandom(req *pkcs11.GenerateRandomReq) (*pkcs11.GenerateRandomResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	resp := &pkcs11.GenerateRandomResp{
		RandomData: make([]byte, req.RandomLen),
	}
	_, err := rand.Reader.Read(resp.RandomData)
	if err != nil {
		return nil, pkcs11.ErrDeviceError
	}
	return resp, nil
}
