//
// Copyright (c) 2021-2023 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"crypto/rsa"
	"log"
	"math/big"
)

// Object implements a PKCS #11 object.
type Object struct {
	Attrs  Template
	Native interface{}
}

// Inflate populates the object's Native member based on object class
// and attributes.
func (obj *Object) Inflate() error {
	uival, err := obj.Attrs.Int(CkaClass)
	if err != nil {
		return err
	}
	class := ObjectClass(uival)

	switch class {
	case CkoPublicKey:
		return obj.inflatePublicKey()
	case CkoPrivateKey:
		return obj.inflatePrivateKey()
	default:
		return nil
	}
}

func (obj *Object) inflatePublicKey() error {
	ival, err := obj.Attrs.Int(CkaKeyType)
	if err != nil {
		return err
	}
	keyType := KeyType(ival)
	switch keyType {
	case CkkRSA:
		e, err := obj.Attrs.BigInt(CkaPublicExponent)
		if err != nil {
			return err
		}
		n, err := obj.Attrs.BigInt(CkaModulus)
		if err != nil {
			return err
		}
		obj.Attrs = obj.Attrs.SetInt(CkaModulusBits, n.BitLen())

		obj.Native = &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}
		return nil

	default:
		log.Printf("\u251c\u2574inflatePublicKey: %s", keyType)
		return nil
	}
}

func (obj *Object) inflatePrivateKey() error {
	ival, err := obj.Attrs.Int(CkaKeyType)
	if err != nil {
		return err
	}
	keyType := KeyType(ival)
	switch keyType {
	case CkkRSA:
		e, err := obj.Attrs.BigInt(CkaPublicExponent)
		if err != nil {
			return err
		}
		n, err := obj.Attrs.BigInt(CkaModulus)
		if err != nil {
			return err
		}
		d, err := obj.Attrs.BigInt(CkaPrivateExponent)
		if err != nil {
			return err
		}

		prime1, err := obj.Attrs.BigInt(CkaPrime1)
		if err != nil {
			return err
		}
		prime2, err := obj.Attrs.BigInt(CkaPrime2)
		if err != nil {
			return err
		}
		obj.Attrs = obj.Attrs.SetInt(CkaModulusBits, n.BitLen())

		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			},
			D:      d,
			Primes: []*big.Int{prime1, prime2},
		}
		err = key.Validate()
		if err != nil {
			log.Printf("%s validation error: %s", keyType, err)
			return ErrTemplateInconsistent
		}
		obj.Native = key
		return nil

	default:
		log.Printf("\u251c\u2574inflatePrivateKey: %s", keyType)
		return nil
	}
}

// HandleAllocator allocates object handles. The handles are not
// guaranteed to be unique.
type HandleAllocator func() (ObjectHandle, error)

// Storage implements object storage.
type Storage interface {
	// Create creates a new object.
	Create(obj *Object) (ObjectHandle, error)

	// Read returns the object by its handle.
	Read(h ObjectHandle) (*Object, error)

	// Update stores a new data for the object.
	Update(h ObjectHandle, obj *Object) error

	// Delete deletes the object by its handle.
	Delete(h ObjectHandle) error

	// Find finds objects matching the template.
	Find(t Template) ([]ObjectHandle, error)
}
