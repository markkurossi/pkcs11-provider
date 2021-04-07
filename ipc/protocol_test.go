//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package ipc

import (
	"testing"
)

func TestType(t *testing.T) {
	tests := []struct {
		Major  int
		Minor  int
		S0     int
		S1     int
		S2     int
		String string
	}{
		{
			2, 0, 0, 0, 0, "2.0-0.0.0",
		},
		{
			2, 40, 1, 2, 3, "2.40-1.2.3",
		},
		{
			3, 0, 5, 7, 1, "3.0-5.7.1",
		},
	}
	for idx, test := range tests {
		typ := NewType(test.Major, test.Minor, test.S0, test.S1, test.S2)
		if typ.Major() != test.Major {
			t.Errorf("Test %d: Major: %d vs %d", idx, typ.Major(), test.Major)
		}
		if typ.Minor() != test.Minor {
			t.Errorf("Test %d: Minor: %d vs %d", idx, typ.Minor(), test.Minor)
		}
		if typ.S0() != test.S0 {
			t.Errorf("Test %d: S0: %d vs %d", idx, typ.S0(), test.S0)
		}
		if typ.S1() != test.S1 {
			t.Errorf("Test %d: S1: %d vs %d", idx, typ.S1(), test.S1)
		}
		if typ.S2() != test.S2 {
			t.Errorf("Test %d: S2: %d vs %d", idx, typ.S2(), test.S2)
		}
	}
}
