//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"bytes"
	"crypto/rand"
	"sync"
)

var (
	_ Storage = &MemoryStorage{}
)

// MemoryStorage implements a memory object storage.
type MemoryStorage struct {
	m       sync.Mutex
	alloc   HandleAllocator
	objects map[ObjectHandle]*Object
}

// NewMemoryStorage creates a new memory object storage.
func NewMemoryStorage(alloc HandleAllocator) *MemoryStorage {
	return &MemoryStorage{
		alloc:   alloc,
		objects: make(map[ObjectHandle]*Object),
	}
}

// Create implements Storage.Create().
func (s *MemoryStorage) Create(obj *Object) (ObjectHandle, error) {
	var uid [16]byte

	// 4.4.1 The CKA_UNIQUE_ID attribute
	//
	// Any time a new object is created, a value for CKA_UNIQUE_ID
	// MUST be generated by the token and stored with the object.
	_, err := rand.Read(uid[:])
	if err != nil {
		return 0, ErrDeviceError
	}
	obj.Attrs = obj.Attrs.Set(CkaUniqueID, uid[:])

	s.m.Lock()
	defer s.m.Unlock()

	for {
		h, err := s.alloc()
		if err != nil {
			return 0, err
		}
		_, ok := s.objects[h]
		if !ok {
			s.objects[h] = obj
			return h, nil
		}
	}
}

// Read implements Storage.Read().
func (s *MemoryStorage) Read(h ObjectHandle) (*Object, error) {
	s.m.Lock()
	defer s.m.Unlock()

	obj, ok := s.objects[h]
	if !ok {
		return nil, ErrObjectHandleInvalid
	}
	return obj, nil
}

// Update implements Storage.Update().
func (s *MemoryStorage) Update(h ObjectHandle, obj *Object) error {
	s.m.Lock()
	defer s.m.Unlock()

	// 4.4.1 The CKA_UNIQUE_ID attribute
	//
	// Any attempt to modify the CKA_UNIQUE_ID attribute of an
	// existing object or to specify the value of the CKA_UNIQUE_ID
	// attribute in the template for an operation that creates one or
	// more objects MUST fail.  Operations failing for this reason
	// return the error code CKR_ATTRIBUTE_READ_ONLY.
	old, ok := s.objects[h]
	if !ok {
		return ErrObjectHandleInvalid
	}
	oldID, err := old.Attrs.OptBytes(CkaUniqueID)
	if err != nil {
		return err
	}
	newID, err := obj.Attrs.OptBytes(CkaUniqueID)
	if err == nil {
		if bytes.Compare(oldID, newID) != 0 {
			return ErrAttributeReadOnly
		}
	}

	s.objects[h] = obj

	return nil
}

// Delete implements Storage.Delete().
func (s *MemoryStorage) Delete(h ObjectHandle) error {
	s.m.Lock()
	defer s.m.Unlock()

	_, ok := s.objects[h]
	if !ok {
		return ErrObjectHandleInvalid
	}
	delete(s.objects, h)

	return nil
}
