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
	"unicode"
)

var (
	types         = make(map[string]TypeInfo)
	reComment     = regexp.MustCompilePOSIX(`^[[:space:]]*//`)
	reBasic       = regexp.MustCompilePOSIX(`^[[:space:]]*type[[:space:]]+([[:^space:]]+)[[:space:]]+([[:^space:]]+)[[:space:]]*$`)
	reStructStart = regexp.MustCompilePOSIX(`^[[:space:]]*type[[:space:]]+([[:^space:]]+)[[:space:]]+struct[[:space:]]*{[[:space:]]*$`)
	reStructField = regexp.MustCompilePOSIX(`^[[:space:]]*(.+)[[:space:]]+([[:^space:]]+)[[:space:]]*$`)
	reStructEnd   = regexp.MustCompilePOSIX(`^[[:space:]]*}[[:space:]]*$`)
	reType        = regexp.MustCompilePOSIX(`^(\[([[:^space:]]+)([[:space:]]+([[:^space:]]+))?\])?([A-Za-z_0-9]+)$`)
)

// TypeInfo provides information about a PKCS #11 API type.
type TypeInfo struct {
	Name      string
	IsBasic   bool
	IsPointer bool
	Basic     string
	Compound  []Field
}

func (t TypeInfo) String() string {
	if t.IsBasic {
		var ptr string
		if t.IsPointer {
			ptr = "*"
		}
		return fmt.Sprintf("type %s %s%s", t.Name, ptr, t.Basic)
	}
	result := fmt.Sprintf("type %s struct {\n", t.Name)
	for _, c := range t.Compound {
		result += fmt.Sprintf("  %s\n", c)
	}
	result += "}"

	return result
}

// GoTypeName returns the Go type name for the type.
func (t TypeInfo) GoTypeName() string {
	if t.IsBasic {
		return GoTypeName(t.Name)
	}
	return GoTypeName(t.Name)
}

// GoType returns the Go type definition for the type.
func (t TypeInfo) GoType() string {
	if t.IsBasic {
		return fmt.Sprintf("type %s %s", GoTypeName(t.Name), GoType(t.Basic))
	}
	result := fmt.Sprintf("type %s struct {\n", GoTypeName(t.Name))

	var max int
	for _, c := range t.Compound {
		parts := strings.Split(c.GoType(false), " ")
		if len(parts[0]) > max {
			max = len(parts[0])
		}
	}

	for _, c := range t.Compound {
		parts := strings.Split(c.GoType(false), " ")
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

var trimPrefixes = []string{
	"p", "ul", "pul", "h",
}

// GoFieldName converts the name to Go field name.
func GoFieldName(name string) string {
	for _, prefix := range trimPrefixes {
		if len(name) <= len(prefix) {
			continue
		}
		if strings.HasPrefix(name, prefix) &&
			unicode.IsUpper(rune(name[len(prefix)])) {
			name = name[len(prefix):]
			break
		}
	}
	return strings.Title(name)
}

// GoFuncName converts the name to Go function name.
func GoFuncName(name string) string {
	return strings.ReplaceAll(name, "C_", "")
}

// GoType returns the Go type name for the type.
func GoType(native string) string {
	return native
}

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
			var ptr bool
			basic := m[2]
			if strings.HasPrefix(basic, "*") {
				basic = basic[1:]
				ptr = true
			}
			types[m[1]] = TypeInfo{
				IsBasic:   true,
				IsPointer: ptr,
				Name:      m[1],
				Basic:     basic,
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
					elType := strings.TrimSpace(m[1])
					elName := strings.TrimSpace(m[2])

					m = reType.FindStringSubmatch(elType)
					if m == nil {
						return fmt.Errorf("invalid type: '%s'", elType)
					}
					typeInfo, ok := types[m[5]]
					if !ok {
						return fmt.Errorf("unknown type: '%s'", m[5])
					}

					fields = append(fields, Field{
						SizeType: m[2],
						SizeName: m[4],
						Type:     typeInfo,
						Name:     elName,
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
	Name     string
	Type     TypeInfo
	Optional bool
	SizeType string
	SizeName string
}

func (f Field) String() string {
	if len(f.SizeType) > 0 {
		var sizeType string
		_, err := strconv.Atoi(f.SizeType)
		if err == nil {
			sizeType = f.SizeType
		}
		return fmt.Sprintf("[%s]%s %s", sizeType, f.Type, f.Name)
	}
	return fmt.Sprintf("%s %s", f.Type, f.Name)
}

// GoType returns the Go type name for the field.
func (f Field) GoType(req bool) string {
	if len(f.SizeType) > 0 {
		// Array.
		if f.Optional && req {
			return fmt.Sprintf("%sSize uint32", GoFieldName(f.Name))
		}

		var sizeType string
		_, err := strconv.Atoi(f.SizeType)
		if err == nil {
			sizeType = f.SizeType
		}
		return fmt.Sprintf("%s [%s]%s",
			GoFieldName(f.Name), sizeType, f.Type.GoTypeName())
	}
	return fmt.Sprintf("%s %s", GoFieldName(f.Name), f.Type.GoTypeName())
}

// Depth computes the depth of nested array types.
func (f *Field) Depth() (int, error) {
	if len(f.SizeType) == 0 {
		return 0, nil
	}
	if f.Type.IsBasic {
		return 0, nil
	}
	depth := 0
	for _, field := range f.Type.Compound {
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
	indent := 2 + level*4

	debug(indent, "// %s\n", f)

	idxName := fmt.Sprintf("%c", 'i'+level)
	idxElName := fmt.Sprintf("%cel", 'i'+level)

	var ctx string
	if level > 0 {
		ctx = fmt.Sprintf("%cel->", 'i'+level-1)
	}

	if len(f.SizeType) == 0 {
		// Single instance.
		if f.Type.IsBasic {
			printf(indent, "vp_buffer_add_%s(&buf, %s%s);\n",
				f.Type.Basic, ctx, f.Name)
		} else {
			printf(indent, "// single not basic\n")
		}
	} else {
		// Array
		if f.Optional {
			printf(indent, `
if (%s == NULL)
  vp_buffer_add_uint32(&buf, 0);
else
  vp_buffer_add_uint32(&buf, *%s);
`,
				f.Name,
				f.SizeName)
		} else if f.Type.IsBasic {
			// Array of basic types.
			size := f.SizeName
			if len(size) == 0 {
				size = f.SizeType
			}
			printf(indent, "vp_buffer_add_%s_arr(&buf, %s%s, %s%s);\n",
				f.Type.Basic,
				ctx, f.Name,
				ctx, size)
		} else {
			// Array of compound type.
			printf(indent, "vp_buffer_add_uint32(&buf, %s%s);\n",
				ctx, f.SizeName)
			printf(indent, "for (%s = 0; %s < %s; %s++)\n",
				idxName, idxName, f.SizeName, idxName)
			printf(indent, "  {\n")
			printf(indent, "    %s *%s = &%s%s[%s];\n\n",
				f.Type, idxElName, ctx, f.Name, idxName)

			for _, c := range f.Type.Compound {
				err := c.Input(level + 1)
				if err != nil {
					return err
				}
			}

			printf(indent, "  }\n")
		}
	}
	return nil
}

// Output generates the output unmarshalling code for the field.
func (f *Field) Output(level int) error {
	indent := 2 + level*4

	debug(indent, "// %s\n", f)

	idxName := fmt.Sprintf("%c", 'i'+level)
	idxElName := fmt.Sprintf("%cel", 'i'+level)

	var ctx string
	if level > 0 {
		ctx = fmt.Sprintf("%cel->", 'i'+level-1)
	}

	if len(f.SizeType) == 0 {
		// Single instance.
		if f.Type.IsBasic {
			printf(indent, "*%s%s = vp_buffer_get_%s(&buf);\n",
				ctx, f.Name, f.Type.Basic)
		} else {
			printf(indent, "// single not basic\n")
		}
	} else {
		// Array
		if f.Optional {
			printf(indent, `
{
  uint32_t count = vp_buffer_get_uint32(&buf);
  uint32_t i;

  if (%s == NULL)
    {
      *%s = count;
    }
  else if (count > *%s)
    {
      vp_buffer_uninit(&buf);
      return CKR_BUFFER_TOO_SMALL;
    }
  else
    {
      *%s = count;
      for (i = 0; i < count; i++)
        %s[i] = vp_buffer_get_uint32(&buf);
    }
}
`,
				f.Name,
				f.SizeName,
				f.SizeName,
				f.SizeName,
				f.Name)
		} else if f.Type.IsBasic {
			// Array of basic types.
			printf(indent, "vp_buffer_get_%s_arr(&buf, %s%s, &%s%s);\n",
				f.Type.Basic,
				ctx, f.Name,
				ctx, f.SizeName)
		} else {
			// Array of compound type.
			printf(indent, "*%s%s = vp_buffer_get_uint32(&buf);\n",
				ctx, f.SizeName)
			printf(indent, "for (%s = 0; %s < %s; %s++)\n",
				idxName, idxName, f.SizeName, idxName)
			printf(indent, "  {\n")
			printf(indent, "    %s *%s = &%s%s[%s];\n\n",
				f.Type, idxElName, ctx, f.Name, idxName)

			for _, c := range f.Type.Compound {
				err := c.Input(level + 1)
				if err != nil {
					return err
				}
			}

			printf(indent, "  }\n")
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
	typeInfo, ok := types[m[5]]
	if !ok {
		return Field{}, fmt.Errorf("unknown type: '%s'", m[5])
	}
	var optional bool
	if strings.HasSuffix(v, "?") {
		optional = true
		v = v[:len(v)-1]
	}

	return Field{
		SizeType: m[2],
		SizeName: m[4],
		Type:     typeInfo,
		Name:     v,
		Optional: optional,
	}, nil
}
