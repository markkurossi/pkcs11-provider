//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.
//

package pkcs11

import (
	"testing"
)

func TestUnmarshalArray(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x10, // CounterBits
		0x00, 0x00, 0x00, 0x10, // cb length
		0x00, 0x01, 0x02, 0x03, // cb
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	var params AesCtrParams
	err := Unmarshal(data, &params)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if params.CounterBits != 16 {
		t.Errorf("invalid counter bits: got %v, expected 16",
			params.CounterBits)
	}
	for i := 0; i < len(params.Cb); i++ {
		if params.Cb[i] != byte(i) {
			t.Errorf("invalid Cb[%d]: got %d, expected %d",
				i, params.Cb[i], i)
		}
	}
}

func TestUnmarshalSlice(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x10, // Type
		0x00, 0x00, 0x00, 0x10, // Value length
		0x00, 0x01, 0x02, 0x03, // Value
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	var attr Attribute
	err := Unmarshal(data, &attr)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if attr.Type != 16 {
		t.Errorf("invalid type: got %v, expected 16", attr.Type)
	}
	for i := 0; i < len(attr.Value); i++ {
		if attr.Value[i] != byte(i) {
			t.Errorf("invalid Value[%d]: got %d, expected %d",
				i, attr.Value[i], i)
		}
	}
}
