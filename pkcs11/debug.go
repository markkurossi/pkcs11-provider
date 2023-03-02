//
// Copyright (c) 2021-2023 Markku Rossi.
//
// All rights reserved.
//

package pkcs11

import (
	"encoding/hex"
	"fmt"
	"os"

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
		v, err := attr.Uint()
		if err != nil {
			return err.Error()
		}
		return ObjectClass(v).String()

	case CkaKeyType:
		v, err := attr.Uint()
		if err != nil {
			return err.Error()
		}
		return KeyType(v).String()

	case CkaValueLen:
		v, err := attr.Uint()
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("%v", v)

	case CkaLabel:
		return string(attr.Value)
	}
	return "???"
}

func (tmpl Template) Print() {
	tab := tabulate.New(tabulate.UnicodeLight)
	tab.Header("Attribute").SetAlign(tabulate.ML)
	tab.Header("Value").SetAlign(tabulate.ML)

	for _, attr := range tmpl {
		row := tab.Row()
		row.Column(attr.Type.String())
		row.Column(attrValueString(attr))
	}
	tab.Print(os.Stdout)
}
