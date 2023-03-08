//
// Copyright (c) 2021-2023 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strconv"

	"github.com/markkurossi/go-libs/uuid"
	"github.com/markkurossi/pkcs11-provider/pkcs11"
)

var (
	reVersion = regexp.MustCompilePOSIX(`^[[:^digit:]]*([[:digit:]]+)\.([[:digit:]]+)`)

	fwVersion = pkcs11.Version{
		Major: 0,
		Minor: 1,
	}
	manufacturerID = []pkcs11.UTF8Char("mtr@iki.fi")
)

// Mechanimsm parameters.
const (
	RSAMinKeySize = 512
	RSAMaxKeySize = 8192
	AESMinKeySize = 16
	AESMaxKeySize = 32
)

var mechanisms = map[pkcs11.MechanismType]pkcs11.MechanismInfo{
	pkcs11.CkmRSAPKCSKeyPairGen: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags:      pkcs11.CkfGenerateKeyPair,
	},
	pkcs11.CkmRSAPKCS: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA224RSAPKCS: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA256RSAPKCS: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA384RSAPKCS: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA512RSAPKCS: {
		MinKeySize: RSAMinKeySize,
		MaxKeySize: RSAMaxKeySize,
		Flags: pkcs11.CkfMessageEncrypt | pkcs11.CkfMessageDecrypt |
			pkcs11.CkfMessageSign | pkcs11.CkfMessageVerify |
			pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfSign |
			pkcs11.CkfVerify,
	},
	pkcs11.CkmSHA224: {
		Flags: pkcs11.CkfDigest,
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
	pkcs11.CkmAESKeyGen: {
		MinKeySize: AESMinKeySize,
		MaxKeySize: AESMaxKeySize,
		Flags:      pkcs11.CkfGenerate,
	},
	pkcs11.CkmAESECB: {
		MinKeySize: AESMinKeySize,
		MaxKeySize: AESMaxKeySize,
		Flags:      pkcs11.CkfGenerate,
	},
	pkcs11.CkmAESGCM: {
		MinKeySize: AESMinKeySize,
		MaxKeySize: AESMaxKeySize,
		Flags:      pkcs11.CkfEncrypt | pkcs11.CkfDecrypt | pkcs11.CkfGenerate,
	},
	pkcs11.CkmAESCTR: {
		MinKeySize: AESMinKeySize,
		MaxKeySize: AESMaxKeySize,
		Flags:      pkcs11.CkfGenerate,
	},
	pkcs11.CkmAESCBC: {
		MinKeySize: AESMinKeySize,
		MaxKeySize: AESMaxKeySize,
		Flags:      pkcs11.CkfGenerate,
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
	storage pkcs11.Storage
	session *Session
}

// Initialize implements pkcs11.Provider.Initialize().
func (p *Provider) Initialize() (*pkcs11.InitializeResp, error) {
	return &pkcs11.InitializeResp{
		ProviderID: p.id,
	}, nil
}

// GetInfo implements the Provider.GetInfo().
func (p *Provider) GetInfo() (*pkcs11.GetInfoResp, error) {
	info := pkcs11.Info{
		CryptokiVersion: pkcs11.Version{
			Major: 3,
			Minor: 0,
		},
		Flags:          0,
		LibraryVersion: fwVersion,
	}
	copy(info.ManufacturerID[:], manufacturerID)
	copy(info.LibraryDescription[:], []pkcs11.UTF8Char("Go PKCS #11 Provider"))

	return &pkcs11.GetInfoResp{
		Info: info,
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

	info := pkcs11.SlotInfo{
		Flags:           pkcs11.CkfTokenPresent,
		HardwareVersion: goVersion(),
		FirmwareVersion: fwVersion,
	}
	copy(info.SlotDescription[:], []pkcs11.UTF8Char("Go crypto library"))
	copy(info.ManufacturerID[:], manufacturerID)

	return &pkcs11.GetSlotInfoResp{
		Info: info,
	}, nil
}

// GetTokenInfo implements the Provider.GetTokenInfo().
func (p *Provider) GetTokenInfo(req *pkcs11.GetTokenInfoReq) (*pkcs11.GetTokenInfoResp, error) {
	if req.SlotID != 0 {
		return nil, pkcs11.ErrSlotIDInvalid
	}

	info := pkcs11.TokenInfo{
		Flags:           pkcs11.CkfRNG | pkcs11.CkfClockOnToken,
		HardwareVersion: goVersion(),
		FirmwareVersion: fwVersion,
	}
	copy(info.ManufacturerID[:], []pkcs11.UTF8Char("www.golang.org"))
	copy(info.Model[:], []pkcs11.UTF8Char("Software"))

	return &pkcs11.GetTokenInfoResp{
		Info: info,
	}, nil
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

// CloseSession implements the Provider.CloseSession().
func (p *Provider) CloseSession() error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	err := CloseSession(p.session.ID)
	if err != nil {
		return err
	}
	p.session = nil

	return nil
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

// Logout implements the Provider.Logout().
func (p *Provider) Logout() error {
	return nil
}

// CreateObject implements the Provider.CreateObject().
func (p *Provider) CreateObject(req *pkcs11.CreateObjectReq) (*pkcs11.CreateObjectResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	if debug {
		for _, attr := range req.Template {
			fmt.Printf("\u251c\u2500\u2500\u2500\u2500\u2574%s:\n", attr.Type)
			if len(attr.Value) > 0 {
				fmt.Printf("%s", hex.Dump(attr.Value))
			}
		}
	}
	token, err := req.Template.OptBool(pkcs11.CkaToken)
	if err != nil {
		return nil, err
	}
	var storage pkcs11.Storage
	if token {
		storage = p.parent.storage
	} else {
		storage = p.session.storage
	}

	obj := &pkcs11.Object{
		Attrs: req.Template,
	}

	// 4.4.1 The CKA_UNIQUE_ID attribute
	//
	// Any time a new object is created, a value for CKA_UNIQUE_ID
	// MUST be generated by the token and stored with the object.
	uuid, err := uuid.New()
	if err != nil {
		return nil, pkcs11.ErrDeviceError
	}
	obj.Attrs = obj.Attrs.Set(pkcs11.CkaUniqueID, []byte(uuid.String()))

	err = obj.Inflate()
	if err != nil {
		return nil, err
	}
	handle, err := storage.Create(obj)
	if err != nil {
		return nil, err
	}

	return &pkcs11.CreateObjectResp{
		Object: handle,
	}, nil
}

// CopyObject implements the Provider.CopyObject().
func (p *Provider) CopyObject(req *pkcs11.CopyObjectReq) (*pkcs11.CopyObjectResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	obj, err := p.readObject(req.Object)
	if err != nil {
		return nil, err
	}
	attrs := obj.Attrs
	for _, a := range req.Template {
		if debug {
			fmt.Printf("\u251c\u2500\u2500\u2500\u2500\u2574%s:\n", a.Type)
			if len(a.Value) > 0 {
				fmt.Printf("%s", hex.Dump(a.Value))
			}
		}
		switch a.Type {
		case pkcs11.CkaSensitive:
			sensitive, err := a.Bool()
			if err != nil {
				return nil, err
			}
			if !sensitive {
				attrs = attrs.SetBool(pkcs11.CkaAlwaysSensitive, false)
			}
		case pkcs11.CkaExtractable:
			extractable, err := a.Bool()
			if err != nil {
				return nil, err
			}
			if extractable {
				attrs = attrs.SetBool(pkcs11.CkaNeverExtractable, false)
			}
		}
		attrs = attrs.Set(a.Type, a.Value)
	}
	token, err := attrs.OptBool(pkcs11.CkaToken)
	if err != nil {
		return nil, err
	}
	var storage pkcs11.Storage
	if token {
		storage = p.parent.storage
	} else {
		storage = p.session.storage
	}

	// 4.4.1 The CKA_UNIQUE_ID attribute
	//
	// Any time a new object is created, a value for CKA_UNIQUE_ID
	// MUST be generated by the token and stored with the object.
	uuid, err := uuid.New()
	if err != nil {
		return nil, pkcs11.ErrDeviceError
	}
	attrs = attrs.Set(pkcs11.CkaUniqueID, []byte(uuid.String()))

	nobj := &pkcs11.Object{
		Attrs:  attrs,
		Native: obj.Native,
	}
	err = nobj.Inflate()
	if err != nil {
		return nil, err
	}
	handle, err := storage.Create(nobj)
	if err != nil {
		return nil, err
	}

	return &pkcs11.CopyObjectResp{
		NewObject: handle,
	}, nil
}

// DestroyObject implements the Provider.DestroyObject().
func (p *Provider) DestroyObject(req *pkcs11.DestroyObjectReq) error {
	if req.Object&FlagToken != 0 {
		return p.parent.storage.Delete(req.Object)
	}
	return p.session.storage.Delete(req.Object)
}

func (p *Provider) readObject(h pkcs11.ObjectHandle) (*pkcs11.Object, error) {
	var storage pkcs11.Storage
	if h&FlagToken != 0 {
		storage = p.parent.storage
	} else {
		storage = p.session.storage
	}

	return storage.Read(h)
}

// GetAttributeValue implements the Provider.GetAttributeValue().
func (p *Provider) GetAttributeValue(req *pkcs11.GetAttributeValueReq) (*pkcs11.GetAttributeValueResp, error) {
	obj, err := p.readObject(req.Object)
	if err != nil {
		return nil, err
	}

	var result pkcs11.Template
	for _, attr := range req.Template {
		if debug {
			fmt.Printf("\u251c\u2500\u2500\u2500\u2500\u2574%s\n", attr.Type)
		}
		v, _ := obj.Attrs.OptBytes(attr.Type)
		result = append(result, pkcs11.Attribute{
			Type:  attr.Type,
			Value: v,
		})
	}

	return &pkcs11.GetAttributeValueResp{
		Template: result,
	}, nil
}

// FindObjectsInit implements the Provider.FindObjectsInit().
func (p *Provider) FindObjectsInit(req *pkcs11.FindObjectsInitReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.FindObjects != nil {
		return pkcs11.ErrOperationActive
	}
	if debug {
		for _, attr := range req.Template {
			fmt.Printf("\u251c\u2500\u2500\u2500\u2500\u2574%s:\n", attr.Type)
			if len(attr.Value) > 0 {
				fmt.Printf("%s", hex.Dump(attr.Value))
			}
		}
	}
	sessionHandles, err := p.session.storage.Find(req.Template)
	if err != nil {
		return err
	}
	tokenHandles, err := p.parent.storage.Find(req.Template)
	if err != nil {
		return err
	}
	p.session.FindObjects = &FindObjects{
		Handles: append(sessionHandles, tokenHandles...),
	}

	return nil
}

// FindObjects implements the Provider.FindObjects().
func (p *Provider) FindObjects(req *pkcs11.FindObjectsReq) (*pkcs11.FindObjectsResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	if p.session.FindObjects == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}
	count := len(p.session.FindObjects.Handles)
	if count > int(req.MaxObjectCount) {
		count = int(req.MaxObjectCount)
	}
	result := make([]pkcs11.ObjectHandle, count)
	copy(result, p.session.FindObjects.Handles[:count])
	p.session.FindObjects.Handles = p.session.FindObjects.Handles[count:]

	return &pkcs11.FindObjectsResp{
		ObjectLen: count,
		Object:    result,
	}, nil
}

// FindObjectsFinal implements the Provider.FindObjectsFinal().
func (p *Provider) FindObjectsFinal() error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.FindObjects == nil {
		return pkcs11.ErrOperationNotInitialized
	}
	p.session.FindObjects = nil
	return nil
}

// EncryptInit implements the Provider.EncryptInit().
func (p *Provider) EncryptInit(req *pkcs11.EncryptInitReq) (*pkcs11.EncryptInitResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	if p.session.Encrypt != nil {
		return nil, pkcs11.ErrOperationActive
	}
	obj, err := p.readObject(req.Key)
	if err != nil {
		log.Printf("readObject failed: key=%x, %v\n", req.Key, err)
		return nil, err
	}
	key, ok := obj.Native.([]byte)
	if !ok {
		log.Printf("!key: obj.Native=%v(%T)", obj.Native, obj.Native)
		return nil, pkcs11.ErrKeyHandleInvalid
	}
	log.Printf("\u251c\u2500\u2500\u2500\u2500\u2574mechanism: %v",
		req.Mechanism.Mechanism)

	resp := &pkcs11.EncryptInitResp{}

	switch req.Mechanism.Mechanism {
	case pkcs11.CkmAESECB:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, pkcs11.ErrKeySizeRange
		}
		p.session.Encrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			Block:     b,
			Buffer:    make([]byte, 0, b.BlockSize()),
		}
		return resp, nil

	case pkcs11.CkmAESCBC, pkcs11.CkmAESCBCPad:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, pkcs11.ErrKeySizeRange
		}
		p.session.Encrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			BlockMode: cipher.NewCBCEncrypter(b, req.Mechanism.Parameter),
			Buffer:    make([]byte, 0, b.BlockSize()),
		}
		return resp, nil

	case pkcs11.CkmAESGCM:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, pkcs11.ErrKeySizeRange
		}
		aead, err := cipher.NewGCM(b)
		if err != nil {
			return nil, pkcs11.ErrDeviceError
		}
		var params pkcs11.GcmParams
		err = pkcs11.Unmarshal(req.Mechanism.Parameter, &params)
		if err != nil {
			log.Printf("\u251c\u2500\u2500\u2574pkcs11.Unmarshal: %v", err)
			return nil, pkcs11.ErrMechanismParamInvalid
		}
		if len(params.Iv) != 12 {
			log.Printf("\u251c\u2500\u2500\u2574%s: invalid IV length %v, expected 12",
				req.Mechanism.Mechanism, len(params.Iv))
			return nil, pkcs11.ErrMechanismParamInvalid
		}
		if params.IvBits == 0 {
			// Token generated IV.
			_, err = rand.Read(params.Iv)
			if err != nil {
				return nil, pkcs11.ErrDeviceError
			}
			resp.Iv = params.Iv
		}

		if params.TagBits != 128 {
			log.Printf("\u251c\u2500\u2500\u2524invalid tag length %v, expected 128",
				params.TagBits)
			return nil, pkcs11.ErrMechanismParamInvalid
		}

		p.session.Encrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			AEAD:      aead,
			IV:        params.Iv,
			AAD:       params.AAD,
		}
		return resp, nil

	default:
		log.Printf("\u251c\u2500\u2500\u2524unsupported mechanism %v, key=%x",
			req.Mechanism.Mechanism, req.Key)
		return nil, pkcs11.ErrMechanismInvalid
	}
}

func pkcs7Pad(buf []byte, blockSize int) []byte {
	padLen := blockSize - len(buf)%blockSize
	if padLen == 0 {
		padLen = blockSize
	}
	resultLen := len(buf) + padLen
	result := make([]byte, resultLen)
	copy(result, buf)
	for i := 0; i < padLen; i++ {
		result[resultLen-1-i] = byte(padLen)
	}

	return result
}

// Encrypt implements the Provider.Encrypt().
func (p *Provider) Encrypt(req *pkcs11.EncryptReq) (*pkcs11.EncryptResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	enc := p.session.Encrypt
	if enc == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}
	resp := &pkcs11.EncryptResp{
		EncryptedDataLen: len(req.Data),
	}
	// Block size alignment is checked below based on the algorithm.
	switch p.session.Encrypt.Mechanism {
	case pkcs11.CkmAESECB:
		blockSize := enc.Block.BlockSize()
		if len(req.Data)%blockSize != 0 {
			p.session.Encrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		if req.EncryptedDataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		for i := 0; i < resp.EncryptedDataLen; i += blockSize {
			enc.Block.Encrypt(req.Data[i:], req.Data[i:])
		}
		resp.EncryptedData = req.Data

	case pkcs11.CkmAESCBC:
		if len(req.Data)%enc.BlockMode.BlockSize() != 0 {
			p.session.Encrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		if req.EncryptedDataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		p.session.Encrypt.BlockMode.CryptBlocks(req.Data, req.Data)
		resp.EncryptedData = req.Data

	case pkcs11.CkmAESCBCPad:
		blockSize := p.session.Encrypt.BlockMode.BlockSize()
		padLen := blockSize - len(req.Data)%blockSize
		if padLen == 0 {
			padLen = blockSize
		}
		resp.EncryptedDataLen = len(req.Data) + padLen
		if req.EncryptedDataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		resp.EncryptedData = pkcs7Pad(req.Data, blockSize)

		p.session.Encrypt.BlockMode.CryptBlocks(resp.EncryptedData,
			resp.EncryptedData)

	case pkcs11.CkmAESGCM:
		if debug {
			log.Printf("AEAD: IV: %x (%d), AAD: %x (%d)",
				p.session.Encrypt.IV, len(p.session.Encrypt.IV),
				p.session.Encrypt.AAD, len(p.session.Encrypt.AAD))
		}
		resp.EncryptedDataLen += p.session.Encrypt.AEAD.Overhead()
		if req.EncryptedDataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		resp.EncryptedData = make([]byte, resp.EncryptedDataLen)
		resp.EncryptedData = p.session.Encrypt.AEAD.Seal(resp.EncryptedData[:0],
			p.session.Encrypt.IV, req.Data, p.session.Encrypt.AAD)
		resp.EncryptedDataLen = len(resp.EncryptedData)

	default:
		p.session.Encrypt = nil
		return nil, pkcs11.ErrFunctionNotSupported
	}

	p.session.Encrypt = nil
	return resp, nil
}

// EncryptUpdate implements the Provider.EncryptUpdate().
func (p *Provider) EncryptUpdate(req *pkcs11.EncryptUpdateReq) (*pkcs11.EncryptUpdateResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	enc := p.session.Encrypt
	if enc == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}

	// Resolve output length.
	var blockSize int
	switch enc.Mechanism {
	case pkcs11.CkmAESECB:
		blockSize = enc.Block.BlockSize()

	case pkcs11.CkmAESCBC, pkcs11.CkmAESCBCPad:
		blockSize = enc.BlockMode.BlockSize()

	default:
		return nil, pkcs11.ErrFunctionNotSupported
	}
	numBlocks := (len(enc.Buffer) + len(req.Part)) / blockSize

	resp := &pkcs11.EncryptUpdateResp{
		EncryptedPartLen: numBlocks * blockSize,
	}
	if req.EncryptedPartSize == 0 {
		// Querying output buffer size.
		return resp, nil
	}

	// Create output buffer.
	resp.EncryptedPart = make([]byte, resp.EncryptedPartLen)
	n := copy(resp.EncryptedPart, enc.Buffer)
	limit := resp.EncryptedPartLen - n
	copy(resp.EncryptedPart[n:], req.Part[:limit])

	// Save any trailing data.
	n = copy(enc.Buffer[0:cap(enc.Buffer)], req.Part[limit:])
	enc.Buffer = enc.Buffer[:n]

	switch enc.Mechanism {
	case pkcs11.CkmAESECB:
		for i := 0; i < resp.EncryptedPartLen; i += blockSize {
			enc.Block.Encrypt(resp.EncryptedPart[i:], resp.EncryptedPart[i:])
		}

	case pkcs11.CkmAESCBC, pkcs11.CkmAESCBCPad:
		enc.BlockMode.CryptBlocks(resp.EncryptedPart, resp.EncryptedPart)

	default:
		return nil, pkcs11.ErrFunctionNotSupported
	}

	return resp, nil
}

// EncryptFinal implements the Provider.EncryptFinal().
func (p *Provider) EncryptFinal(req *pkcs11.EncryptFinalReq) (*pkcs11.EncryptFinalResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	enc := p.session.Encrypt
	if enc == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}

	resp := &pkcs11.EncryptFinalResp{}

	switch enc.Mechanism {
	case pkcs11.CkmAESECB, pkcs11.CkmAESCBC:
		if len(enc.Buffer) != 0 {
			p.session.Encrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}

	case pkcs11.CkmAESCBCPad:
		blockSize := enc.BlockMode.BlockSize()
		resp.LastEncryptedPartLen = blockSize
		if req.LastEncryptedPartSize == 0 {
			// Querying buffer size.
			return resp, nil
		}
		resp.LastEncryptedPart = pkcs7Pad(enc.Buffer, blockSize)
		enc.BlockMode.CryptBlocks(resp.LastEncryptedPart,
			resp.LastEncryptedPart)

	default:
		return nil, pkcs11.ErrFunctionNotSupported
	}

	p.session.Encrypt = nil
	return resp, nil
}

// DecryptInit implements the Provider.DecryptInit().
func (p *Provider) DecryptInit(req *pkcs11.DecryptInitReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.Decrypt != nil {
		return pkcs11.ErrOperationActive
	}
	obj, err := p.readObject(req.Key)
	if err != nil {
		log.Printf("readObject failed: key=%x, %v\n", req.Key, err)
		return err
	}
	key, ok := obj.Native.([]byte)
	if !ok {
		log.Printf("!key: obj.Native=%v(%T)", obj.Native, obj.Native)
		return pkcs11.ErrKeyHandleInvalid
	}
	log.Printf("\u251c\u2500\u2500\u2500\u2500\u2574mechanism: %v",
		req.Mechanism.Mechanism)

	switch req.Mechanism.Mechanism {
	case pkcs11.CkmAESECB:
		b, err := aes.NewCipher(key)
		if err != nil {
			return pkcs11.ErrKeySizeRange
		}
		p.session.Decrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			Block:     b,
		}
		return nil

	case pkcs11.CkmAESCBC, pkcs11.CkmAESCBCPad:
		b, err := aes.NewCipher(key)
		if err != nil {
			return pkcs11.ErrKeySizeRange
		}
		p.session.Decrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			BlockMode: cipher.NewCBCDecrypter(b, req.Mechanism.Parameter),
		}
		return nil

	case pkcs11.CkmAESGCM:
		b, err := aes.NewCipher(key)
		if err != nil {
			return pkcs11.ErrKeySizeRange
		}
		aead, err := cipher.NewGCM(b)
		if err != nil {
			return pkcs11.ErrDeviceError
		}
		var params pkcs11.GcmParams
		err = pkcs11.Unmarshal(req.Mechanism.Parameter, &params)
		if err != nil {
			log.Printf("\u251c\u2500\u2500\u2574pkcs11.Unmarshal: %v", err)
			return pkcs11.ErrMechanismParamInvalid
		}
		if params.IvBits != 96 {
			log.Printf("\u251c\u2500\u2500\u2574%s: invalid IV length %v, expected 96",
				req.Mechanism.Mechanism, params.IvBits)
			return pkcs11.ErrMechanismParamInvalid
		}
		if params.TagBits != 128 {
			log.Printf("\u251c\u2500\u2500\u2524invalid tag length %v, expected 128",
				params.TagBits)
			return pkcs11.ErrMechanismParamInvalid
		}

		p.session.Decrypt = &EncDec{
			Mechanism: req.Mechanism.Mechanism,
			AEAD:      aead,
			IV:        params.Iv,
			AAD:       params.AAD,
		}
		return nil

	default:
		log.Printf("\u251c\u2500\u2500\u2524unsupported mechanism %v, key=%x",
			req.Mechanism.Mechanism, req.Key)
		return pkcs11.ErrMechanismInvalid
	}
}

// Decrypt implements the Provider.Decrypt().
func (p *Provider) Decrypt(req *pkcs11.DecryptReq) (*pkcs11.DecryptResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	dec := p.session.Decrypt
	if dec == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}
	resp := &pkcs11.DecryptResp{
		DataLen: len(req.EncryptedData),
	}
	// Block size alignment is checked below based on the algorithm.
	switch dec.Mechanism {
	case pkcs11.CkmAESECB:
		blockSize := dec.Block.BlockSize()
		if len(req.EncryptedData)%blockSize != 0 {
			p.session.Decrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		if req.DataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		for i := 0; i < resp.DataLen; i += blockSize {
			dec.Block.Decrypt(req.EncryptedData[i:], req.EncryptedData[i:])
		}
		resp.Data = req.EncryptedData

	case pkcs11.CkmAESCBC:
		if len(req.EncryptedData)%p.session.Decrypt.BlockMode.BlockSize() != 0 {
			p.session.Decrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		if req.DataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		p.session.Decrypt.BlockMode.CryptBlocks(req.EncryptedData,
			req.EncryptedData)
		resp.Data = req.EncryptedData

	case pkcs11.CkmAESCBCPad:
		blockSize := p.session.Decrypt.BlockMode.BlockSize()
		if len(req.EncryptedData) == 0 ||
			len(req.EncryptedData)%blockSize != 0 {
			p.session.Decrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		if req.DataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		p.session.Decrypt.BlockMode.CryptBlocks(req.EncryptedData,
			req.EncryptedData)
		padLen := int(req.EncryptedData[len(req.EncryptedData)-1])
		if padLen > len(req.EncryptedData) {
			p.session.Decrypt = nil
			return nil, pkcs11.ErrDataLenRange
		}
		resp.DataLen = len(req.EncryptedData) - padLen
		resp.Data = req.EncryptedData[:resp.DataLen]

	case pkcs11.CkmAESGCM:
		if debug {
			log.Printf("AEAD: IV: %x (%d), AAD: %x (%d)",
				p.session.Decrypt.IV, len(p.session.Decrypt.IV),
				p.session.Decrypt.AAD, len(p.session.Decrypt.AAD))
		}
		if req.DataSize == 0 {
			// Querying output buffer size.
			return resp, nil
		}
		var err error
		resp.Data, err = p.session.Decrypt.AEAD.Open(req.EncryptedData[:0],
			p.session.Decrypt.IV, req.EncryptedData, p.session.Decrypt.AAD)
		if err != nil {
			p.session.Decrypt = nil
			return nil, pkcs11.ErrFunctionFailed
		}
		resp.DataLen = len(resp.Data)

	default:
		p.session.Decrypt = nil
		return nil, pkcs11.ErrFunctionNotSupported
	}

	p.session.Decrypt = nil
	return resp, nil
}

// DecryptUpdate implements the Provider.DecryptUpdate().
func (p *Provider) DecryptUpdate(req *pkcs11.DecryptUpdateReq) (*pkcs11.DecryptUpdateResp, error) {
	return nil, pkcs11.ErrFunctionNotSupported
}

// DecryptFinal implements the Provider.DecryptFinal().
func (p *Provider) DecryptFinal(req *pkcs11.DecryptFinalReq) (*pkcs11.DecryptFinalResp, error) {
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
	case pkcs11.CkmSHA224:
		p.session.Digest = sha256.New224()
		return nil

	case pkcs11.CkmSHA256:
		p.session.Digest = sha256.New()
		return nil

	case pkcs11.CkmSHA384:
		p.session.Digest = sha512.New384()
		return nil

	case pkcs11.CkmSHA512:
		p.session.Digest = sha512.New()
		return nil

	default:
		log.Printf("DigestInit: Mechanism=%v", req.Mechanism.Mechanism)
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

// SignInit implements the Provider.SignInit().
func (p *Provider) SignInit(req *pkcs11.SignInitReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.Sign != nil {
		return pkcs11.ErrOperationActive
	}

	sign, err := NewSignVerify(req.Mechanism)
	if err != nil {
		return err
	}

	obj, err := p.readObject(req.Key)
	if err != nil {
		return err
	}
	// XXX Check object is valid for the operation.
	sign.Key = obj.Native

	p.session.Sign = sign

	return nil
}

// Sign implements the Provider.Sign().
func (p *Provider) Sign(req *pkcs11.SignReq) (*pkcs11.SignResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	sign := p.session.Sign
	if sign == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}

	resp := new(pkcs11.SignResp)
	var signature []byte
	var err error

	switch priv := sign.Key.(type) {
	case *rsa.PrivateKey:
		resp.SignatureLen = priv.PublicKey.Size()
		if req.SignatureSize == 0 {
			return resp, nil
		}
		sign.Digest.Write(req.Data)
		digest := sign.Digest.Sum(nil)
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, sign.Hash, digest)
		if err != nil {
			log.Printf("Sign: rsa.SignPKCS1v15: %s", err)
			p.session.Sign = nil
			return nil, pkcs11.ErrFunctionFailed
		}

	default:
		log.Printf("Sign: sign not supported for key %T", priv)
		p.session.Sign = nil
		return nil, pkcs11.ErrDeviceError
	}

	resp.Signature = signature
	p.session.Sign = nil

	return resp, nil
}

// SignUpdate implements the Provider.SignUpdate().
func (p *Provider) SignUpdate(req *pkcs11.SignUpdateReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	sign := p.session.Sign
	if sign == nil {
		return pkcs11.ErrOperationNotInitialized
	}
	sign.Digest.Write(req.Part)
	return nil
}

// SignFinal implements the Provider.SignFinal().
func (p *Provider) SignFinal(req *pkcs11.SignFinalReq) (*pkcs11.SignFinalResp, error) {
	if p.session == nil {
		return nil, pkcs11.ErrSessionHandleInvalid
	}
	sign := p.session.Sign
	if sign == nil {
		return nil, pkcs11.ErrOperationNotInitialized
	}

	resp := new(pkcs11.SignFinalResp)
	var signature []byte
	var err error

	switch priv := sign.Key.(type) {
	case *rsa.PrivateKey:
		resp.SignatureLen = priv.PublicKey.Size()
		if req.SignatureSize == 0 {
			return resp, nil
		}
		digest := sign.Digest.Sum(nil)
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, sign.Hash, digest)
		if err != nil {
			log.Printf("SignFinal: rsa.SignPKCS1v15: %s", err)
			p.session.Sign = nil
			return nil, pkcs11.ErrFunctionFailed
		}

	default:
		log.Printf("SignFinal: sign not supported for key %T", priv)
		p.session.Sign = nil
		return nil, pkcs11.ErrDeviceError
	}

	resp.Signature = signature
	p.session.Sign = nil

	return resp, nil
}

// VerifyInit implements the Provider.VerifyInit().
func (p *Provider) VerifyInit(req *pkcs11.VerifyInitReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	if p.session.Verify != nil {
		return pkcs11.ErrOperationActive
	}

	verify, err := NewSignVerify(req.Mechanism)
	if err != nil {
		return err
	}

	obj, err := p.readObject(req.Key)
	if err != nil {
		return err
	}
	// XXX Check object is valid for the operation.
	verify.Key = obj.Native

	p.session.Verify = verify

	return nil
}

// Verify implements the Provider.Verify().
func (p *Provider) Verify(req *pkcs11.VerifyReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	verify := p.session.Verify
	if verify == nil {
		return pkcs11.ErrOperationNotInitialized
	}

	switch pub := verify.Key.(type) {
	case *rsa.PublicKey:
		verify.Digest.Write(req.Data)
		digest := verify.Digest.Sum(nil)
		err := rsa.VerifyPKCS1v15(pub, verify.Hash, digest, req.Signature)
		if err != nil {
			log.Printf("Verify: rsa.VerifyPKCS1v15: %s", err)
			p.session.Verify = nil
			return pkcs11.ErrSignatureInvalid
		}

	default:
		log.Printf("Verify: verify not supported for key %T", pub)
		p.session.Verify = nil
		return pkcs11.ErrDeviceError
	}

	p.session.Verify = nil

	return nil
}

// VerifyUpdate implements the Provider.VerifyUpdate().
func (p *Provider) VerifyUpdate(req *pkcs11.VerifyUpdateReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	verify := p.session.Verify
	if verify == nil {
		return pkcs11.ErrOperationNotInitialized
	}

	verify.Digest.Write(req.Part)

	return nil
}

// VerifyFinal implements the Provider.VerifyFinal().
func (p *Provider) VerifyFinal(req *pkcs11.VerifyFinalReq) error {
	if p.session == nil {
		return pkcs11.ErrSessionHandleInvalid
	}
	verify := p.session.Verify
	if verify == nil {
		return pkcs11.ErrOperationNotInitialized
	}

	switch pub := verify.Key.(type) {
	case *rsa.PublicKey:
		digest := verify.Digest.Sum(nil)
		err := rsa.VerifyPKCS1v15(pub, verify.Hash, digest, req.Signature)
		if err != nil {
			log.Printf("VerifyFinal: rsa.VerifyPKCS1v15: %s", err)
			p.session.Verify = nil
			return pkcs11.ErrSignatureInvalid
		}

	default:
		log.Printf("VerifyFinal: verify not supported for key %T", pub)
		p.session.Verify = nil
		return pkcs11.ErrDeviceError
	}

	p.session.Verify = nil

	return nil
}

// GenerateKey implements the Provider.GenerateKey().
func (p *Provider) GenerateKey(req *pkcs11.GenerateKeyReq) (*pkcs11.GenerateKeyResp, error) {
	info, ok := mechanisms[req.Mechanism.Mechanism]
	if !ok {
		return nil, pkcs11.ErrMechanismInvalid
	}
	cls := req.Template.OptInt(pkcs11.CkaClass, int(pkcs11.CkoSecretKey))
	if pkcs11.ObjectClass(cls) != pkcs11.CkoSecretKey {
		return nil, pkcs11.ErrTemplateIncomplete
	}

	switch req.Mechanism.Mechanism {
	case pkcs11.CkmAESKeyGen:
		size, err := req.Template.Int(pkcs11.CkaValueLen)
		if err != nil {
			return nil, err
		}
		token, err := req.Template.OptBool(pkcs11.CkaToken)
		if err != nil {
			return nil, err
		}
		sensitive, err := req.Template.OptBool(pkcs11.CkaSensitive)
		if err != nil {
			return nil, err
		}
		extractable, err := req.Template.OptBool(pkcs11.CkaExtractable)
		if err != nil {
			return nil, err
		}
		if size < int(info.MinKeySize) || size > int(info.MaxKeySize) {
			return nil, pkcs11.ErrTemplateIncomplete
		}
		var storage pkcs11.Storage
		if token {
			storage = p.parent.storage
		} else {
			storage = p.session.storage
		}
		key := make([]byte, size)
		_, err = rand.Read(key)
		if err != nil {
			log.Printf("rand.Read failed: %s", err)
			return nil, pkcs11.ErrDeviceError
		}
		tmpl := req.Template
		tmpl = tmpl.SetInt(pkcs11.CkaClass, cls)
		tmpl = tmpl.SetBool(pkcs11.CkaToken, token)
		tmpl = tmpl.SetBool(pkcs11.CkaSensitive, sensitive)
		tmpl = tmpl.SetBool(pkcs11.CkaAlwaysSensitive, sensitive)
		tmpl = tmpl.SetBool(pkcs11.CkaExtractable, extractable)
		tmpl = tmpl.SetBool(pkcs11.CkaNeverExtractable, !extractable)
		tmpl = tmpl.SetInt(pkcs11.CkaValueLen, size)
		tmpl = tmpl.SetInt(pkcs11.CkaKeyType, int(pkcs11.CkkAES))

		obj := &pkcs11.Object{
			Attrs:  tmpl,
			Native: key,
		}
		err = obj.Inflate()
		if err != nil {
			return nil, err
		}
		handle, err := storage.Create(obj)
		if err != nil {
			return nil, err
		}

		return &pkcs11.GenerateKeyResp{
			Key: handle,
		}, nil

	default:
		log.Printf("GenerateKey: %s", req.Mechanism)
		log.Printf("Template:")
		for idx, attr := range req.Template {
			log.Printf(" - %d: %s\n", idx, attr.Type)
			if len(attr.Value) > 0 {
				log.Printf("%s", hex.Dump(attr.Value))
			}
		}
		return nil, pkcs11.ErrMechanismInvalid
	}
}

// GenerateKeyPair implements the Provider.GenerateKeyPair().
func (p *Provider) GenerateKeyPair(req *pkcs11.GenerateKeyPairReq) (*pkcs11.GenerateKeyPairResp, error) {
	info, ok := mechanisms[req.Mechanism.Mechanism]
	if !ok {
		return nil, pkcs11.ErrMechanismInvalid
	}
	switch req.Mechanism.Mechanism {
	case pkcs11.CkmRSAPKCSKeyPairGen, pkcs11.CkmRSAX931KeyPairGen:
		bits, err := req.PublicKeyTemplate.Int(pkcs11.CkaModulusBits)
		if err != nil {
			return nil, err
		}
		e, err := req.PublicKeyTemplate.BigInt(pkcs11.CkaPublicExponent)
		if err != nil {
			return nil, err
		}
		token, err := req.PrivateKeyTemplate.OptBool(pkcs11.CkaToken)
		if err != nil {
			return nil, err
		}
		if false {
			log.Printf("bits:\t%d\n", bits)
			log.Printf("e:\t%s\n", e)
			log.Printf("token:\t%v\n", token)
		}
		if bits < int(info.MinKeySize) || bits > int(info.MaxKeySize) {
			return nil, pkcs11.ErrMechanismParamInvalid
		}

		var storage pkcs11.Storage
		if token {
			storage = p.parent.storage
		} else {
			storage = p.session.storage
		}

		key, err := rsa.GenerateKey(rand.Reader, int(bits))
		if err != nil {
			log.Printf("rsa.GenerateKey failed: %s", err)
			return nil, pkcs11.ErrDeviceError
		}

		// Store private key prime factors.
		if len(key.Primes) != 2 {
			log.Printf("rsa.GenerateKey: #primes != 2: %d", len(key.Primes))
			return nil, pkcs11.ErrDeviceError
		}

		privTmpl := req.PrivateKeyTemplate
		privTmpl = privTmpl.Set(pkcs11.CkaPrime1, key.Primes[0].Bytes())
		privTmpl = privTmpl.Set(pkcs11.CkaPrime2, key.Primes[1].Bytes())
		privTmpl = privTmpl.Set(pkcs11.CkaModulus, key.PublicKey.N.Bytes())
		privTmpl = privTmpl.Set(pkcs11.CkaPublicExponent, e.Bytes())
		privTmpl = privTmpl.Set(pkcs11.CkaPrivateExponent, key.D.Bytes())
		privTmpl = privTmpl.SetInt(pkcs11.CkaClass, int(pkcs11.CkoPrivateKey))
		privTmpl = privTmpl.SetInt(pkcs11.CkaKeyType, int(pkcs11.CkkRSA))

		privObj := &pkcs11.Object{
			Attrs: privTmpl,
		}
		err = privObj.Inflate()
		if err != nil {
			return nil, err
		}
		privHandle, err := storage.Create(privObj)
		if err != nil {
			return nil, err
		}

		pubTmpl := req.PublicKeyTemplate
		pubTmpl = pubTmpl.Set(pkcs11.CkaModulus, key.PublicKey.N.Bytes())
		pubTmpl = pubTmpl.Set(pkcs11.CkaPublicExponent, e.Bytes())
		pubTmpl = pubTmpl.SetInt(pkcs11.CkaClass, int(pkcs11.CkoPublicKey))
		pubTmpl = pubTmpl.SetInt(pkcs11.CkaKeyType, int(pkcs11.CkkRSA))

		pubObj := &pkcs11.Object{
			Attrs: pubTmpl,
		}
		err = pubObj.Inflate()
		if err != nil {
			storage.Delete(privHandle)
			return nil, err
		}
		pubHandle, err := storage.Create(pubObj)
		if err != nil {
			storage.Delete(privHandle)
			return nil, err
		}

		return &pkcs11.GenerateKeyPairResp{
			PublicKey:  pubHandle,
			PrivateKey: privHandle,
		}, nil

	default:
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

		return nil, pkcs11.ErrMechanismInvalid
	}
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
