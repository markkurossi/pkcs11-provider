//
// Copyright (c) 2021-2023 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/markkurossi/tabulate"
)

// Debug prints the template to standard output.
func (tmpl Template) Debug() {
	for _, attr := range tmpl {
		fmt.Printf("\u251c\u2500\u2500\u2500\u2500\u2574%s:\n", attr.Type)
		if len(attr.Value) > 0 {
			fmt.Printf("%s", hex.Dump(attr.Value))
		}
	}
}

func attrValueString(attr Attribute) string {
	if len(attr.Value) == 1 {
		if attr.Value[0] == 0 {
			return "false"
		}
		return "true"
	}
	switch attr.Type {
	case CkaClass:
		v, err := attr.Int()
		if err != nil {
			return err.Error()
		}
		return ObjectClass(v).String()

	case CkaLabel:
		return string(attr.Value)

	case CkaKeyType:
		v, err := attr.Int()
		if err != nil {
			return err.Error()
		}
		return KeyType(v).String()

	case CkaValueLen, CkaModulusBits:
		v, err := attr.Int()
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("%v", v)

	default:
		h := fmt.Sprintf("%x", attr.Value)
		var result string
		const limit int = 32
		for len(h) > limit {
			result += h[:limit]
			result += "\n"
			h = h[limit:]
		}
		return result + h
	}
}

// Print pretty-prints the template to standard output.
func (tmpl Template) Print(prefix string) {
	tab := tabulate.New(tabulate.UnicodeLight)
	tab.Header("Attribute").SetAlign(tabulate.TL)
	tab.Header("Value").SetAlign(tabulate.TL)

	for _, attr := range tmpl {
		row := tab.Row()
		row.Column(attr.Type.String())
		row.Column(attrValueString(attr))
	}
	for _, line := range strings.Split(tab.String(), "\n") {
		fmt.Printf("%s%s\n", prefix, line)
	}
}
