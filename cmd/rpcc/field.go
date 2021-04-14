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
	"strconv"
	"strings"
)

// TypeInfo provides information about a PKCS #11 API type.
type TypeInfo struct {
	Name     string
	Basic    bool
	Native   string
	Compound []Field
}

func (t TypeInfo) String() string {
	if t.Basic {
		return fmt.Sprintf("type %s %s", t.Name, t.Native)
	}
	result := fmt.Sprintf("type %s struct {\n", t.Name)
	for _, c := range t.Compound {
		result += fmt.Sprintf("  %s\n", c)
	}
	result += "}"

	return result
}

// GoType returns the Go type name for the type.
func (t TypeInfo) GoType() string {
	if t.Basic {
		return fmt.Sprintf("type %s %s", GoTypeName(t.Name), GoType(t.Native))
	}
	result := fmt.Sprintf("type %s struct {\n", GoTypeName(t.Name))

	var max int
	for _, c := range t.Compound {
		parts := strings.Split(c.GoType(), " ")
		if len(parts[0]) > max {
			max = len(parts[0])
		}
	}

	for _, c := range t.Compound {
		parts := strings.Split(c.GoType(), " ")
		result += fmt.Sprintf("\t%s", parts[0])

		for i := len(parts[0]); i < max; i++ {
			result += " "
		}
		result += " " + strings.Join(parts[1:], " ")
		result += "\n"
	}
	result += "}"

	return result
}

// GoTypeName converts the name to Go type name.
func GoTypeName(name string) string {
	var parts []string

	for _, part := range strings.Split(name, "_") {
		switch part {
		case "CK", "ID":
			parts = append(parts, part)

		case "UTF8CHAR":
			parts = append(parts, "UTF8Char")

		default:
			parts = append(parts, strings.Title(strings.ToLower(part)))
		}
	}
	return strings.Join(parts, "")
}

// GoFuncName converts the name to Go function name.
func GoFuncName(name string) string {
	return strings.ReplaceAll(name, "C_", "")
}

// GoType returns the Go type name for the type.
func GoType(native string) string {
	return native
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
				Basic:  true,
				Name:   m[1],
				Native: m[2],
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
				Name:     name,
				Compound: fields,
			}
			continue
		}

		return fmt.Errorf("unexpected line: %s", line)
	}

	return nil
}

// Field defines a function argument or type field.
type Field struct {
	SizeName    string
	ElementType string
	ElementName string
}

func (f Field) String() string {
	if len(f.SizeName) > 0 {
		var sizeName string
		_, err := strconv.Atoi(f.SizeName)
		if err == nil {
			sizeName = f.SizeName
		}
		return fmt.Sprintf("[%s]%s %s",
			sizeName, f.ElementType, f.ElementName)
	}
	return fmt.Sprintf("%s %s", f.ElementType, f.ElementName)
}

// GoType returns the Go type name for the field.
func (f Field) GoType() string {
	if len(f.SizeName) > 0 {
		var sizeName string
		_, err := strconv.Atoi(f.SizeName)
		if err == nil {
			sizeName = f.SizeName
		}
		return fmt.Sprintf("%s [%s]%s",
			strings.Title(f.ElementName), sizeName, GoTypeName(f.ElementType))
	}
	return fmt.Sprintf("%s %s", strings.Title(f.ElementName),
		GoTypeName(f.ElementType))
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
				indent, typeInfo.Native, ctx, f.ElementName)
		} else {
			printf("%s// single not basic\n", indent)
		}
	} else {
		// Array
		if typeInfo.Basic {
			// Array of basic types.
			printf("%svp_buffer_add_%s_arr(&buf, %s%s, %s%s);\n",
				indent, typeInfo.Native,
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
