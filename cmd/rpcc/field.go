//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// TypeInfo provides information about a PKCS #11 API type.
type TypeInfo struct {
	Basic    bool
	Name     string
	Compound []Field
}

var (
	types         = make(map[string]TypeInfo)
	reComment     = regexp.MustCompilePOSIX(`^[[:space:]]*//`)
	reBasic       = regexp.MustCompilePOSIX(`^[[:space:]]*type[[:space:]]+([[:^space:]]+)[[:space:]]+([[:^space:]]+)[[:space:]]*$`)
	reStructStart = regexp.MustCompilePOSIX(`^[[:space:]]*type[[:space:]]+([[:^space:]]+)[[:space:]]+struct[[:space:]]*{[[:space:]]*$`)
	reStructField = regexp.MustCompilePOSIX(`^[[:space:]]*([[:^space:]]+)[[:space:]]+([[:^space:]]+)`)
	reStructEnd   = regexp.MustCompilePOSIX(`^[[:space:]]*}[[:space:]]*$`)
)

func readTypes(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if reComment.FindStringSubmatch(line) != nil {
			continue
		}
		m := reBasic.FindStringSubmatch(line)
		if m != nil {
			types[m[1]] = TypeInfo{
				Basic: true,
				Name:  m[2],
			}
			continue
		}
		m = reStructStart.FindStringSubmatch(line)
		if m != nil {
			name := m[1]
			var fields []Field

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				line = strings.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if reStructEnd.FindStringSubmatch(line) != nil {
					break
				}
				if reComment.FindStringSubmatch(line) != nil {
					continue
				}
				m = reStructField.FindStringSubmatch(line)
				if m != nil {
					elType := m[1]
					elName := m[2]

					m = reType.FindStringSubmatch(elType)
					if m == nil {
						return fmt.Errorf("invalid type: %s", elType)
					}

					fields = append(fields, Field{
						SizeName:    m[2],
						ElementType: m[3],
						ElementName: elName,
					})
					continue
				}
				return fmt.Errorf("unexpected line: %s", line)
			}

			types[name] = TypeInfo{
				Compound: fields,
			}
			continue
		}

		return fmt.Errorf("unexpected line: %s", line)
	}

	for k, v := range types {
		fmt.Fprintf(os.Stderr, "%s: %v\n", k, v.Basic)
	}

	return nil
}

// Field defines a function argument or type field.
type Field struct {
	SizeName    string
	ElementType string
	ElementName string
}

func (f *Field) String() string {
	if len(f.SizeName) > 0 {
		return fmt.Sprintf("[%s]%s %s",
			f.SizeName, f.ElementType, f.ElementName)
	}
	return fmt.Sprintf("%s %s", f.ElementType, f.ElementName)
}

// Depth computes the depth of nested array types.
func (f *Field) Depth() (int, error) {
	if len(f.SizeName) == 0 {
		return 0, nil
	}
	typeInfo, ok := types[f.ElementType]
	if !ok {
		return 0, fmt.Errorf("depth: unknown type: %s", f.ElementType)
	}
	if typeInfo.Basic {
		return 0, nil
	}
	depth := 0
	for _, field := range typeInfo.Compound {
		d, err := field.Depth()
		if err != nil {
			return 0, err
		}
		if d > depth {
			depth = d
		}
	}
	return 1 + depth, nil
}

// Input generates the input marshalling code for the field.
func (f *Field) Input(level int) error {
	var indent = "  "
	for i := 0; i < level; i++ {
		indent += "    "
	}

	debug("%s// %s\n", indent, f)

	idxName := fmt.Sprintf("%c", 'i'+level)
	idxElName := fmt.Sprintf("%cel", 'i'+level)

	var ctx string
	if level > 0 {
		ctx = fmt.Sprintf("%cel->", 'i'+level-1)
	}

	typeInfo, ok := types[f.ElementType]
	if !ok {
		return fmt.Errorf("input: unknown type: %s", f.ElementType)
	}
	if len(f.SizeName) == 0 {
		// Single instance.
		if typeInfo.Basic {
			printf("%svp_buffer_add_%s(&buf, %s%s);\n",
				indent, typeInfo.Name, ctx, f.ElementName)
		} else {
			printf("%s// single not basic\n", indent)
		}
	} else {
		// Array
		if typeInfo.Basic {
			// Array of basic types.
			printf("%svp_buffer_add_%s_arr(&buf, %s%s, %s%s);\n",
				indent, typeInfo.Name,
				ctx, f.ElementName,
				ctx, f.SizeName)
		} else {
			// Array of compound type.
			printf("%svp_buffer_add_uint32(&buf, %s%s);\n",
				indent, ctx, f.SizeName)
			printf("%sfor (%s = 0; %s < %s; %s++)\n", indent,
				idxName, idxName, f.SizeName, idxName)
			printf("%s  {\n", indent)
			printf("%s    %s *%s = &%s%s[%s];\n\n",
				indent, f.ElementType, idxElName, ctx, f.ElementName, idxName)

			for _, c := range typeInfo.Compound {
				err := c.Input(level + 1)
				if err != nil {
					return err
				}
			}

			printf("%s  }\n", indent)
		}
	}
	return nil
}

func parseField(t, v string) (f Field, err error) {
	m := reType.FindStringSubmatch(t)
	if m == nil {
		err = fmt.Errorf("invalid field type: '%s'", t)
		return
	}
	return Field{
		SizeName:    m[2],
		ElementType: m[3],
		ElementName: v,
	}, nil
}
