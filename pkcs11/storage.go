//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

// Object implements a PKCS #11 object.
type Object struct {
	Attrs  Template
	Native interface{}
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
}
