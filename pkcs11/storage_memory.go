//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
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

	_, ok := s.objects[h]
	if !ok {
		return ErrObjectHandleInvalid
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
