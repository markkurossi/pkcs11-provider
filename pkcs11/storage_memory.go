//
// Copyright (c) 2021, 2023 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"bytes"
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

// Find implements Storage.Find().
func (s *MemoryStorage) Find(t Template) (result []ObjectHandle, err error) {
	s.m.Lock()
	defer s.m.Unlock()

	for handle, obj := range s.objects {
		if obj.Attrs.Match(t) {
			result = append(result, handle)
		}
	}
	return
}
