//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/markkurossi/pkcs11-provider/ipc"
)

var (
	reVersion      = regexp.MustCompilePOSIX(`/\*\*[[:space:]]+Version:[[:space:]]+([[:digit:]]+)\.([[:digit:]]+)`)
	reSection      = regexp.MustCompilePOSIX(`/\*\*[[:space:]]+Section:[[:space:]]+([[:digit:]]+)\.([[:digit:]]+)[[:space:]]*([^\*]+)`)
	reFunction     = regexp.MustCompilePOSIX(`^(C_[a-zA-Z0-9_]+)`)
	reSigStart     = regexp.MustCompilePOSIX(`^[[:space:]]*/\*\*[[:space:]]*$`)
	reSigEnd       = regexp.MustCompilePOSIX(`^[[:space:]]*\*/[[:space:]]*$`)
	reFieldSection = regexp.MustCompilePOSIX(`^[[:space:]]*\*[[:space:]]*([[:alnum:]]+):[[:space:]]*$`)
	reField        = regexp.MustCompilePOSIX(`\*[[:space:]]+([[:^space:]]+)[[:space:]]+([[:^space:]]+)`)
	reType         = regexp.MustCompilePOSIX(`^(\[([A-Za-z_0-9]+)\])?([A-Za-z_0-9]+)$`)

	vMajorLast int
	vMinorLast int

	output     io.WriteCloser = os.Stdout
	outputC    bool
	outputGo   bool
	printInfo  bool
	printDebug bool
)

func main() {
	log.SetFlags(0)
	flag.BoolVar(&outputC, "c", false, "generate C code")
	flag.BoolVar(&outputGo, "go", false, "generate Go code")
	flag.BoolVar(&printInfo, "i", false, "print file information")
	flag.BoolVar(&printDebug, "d", false, "print debug information")
	typeFile := flag.String("t", "", "type information file")
	o := flag.String("o", "", "output file name")
	flag.Parse()

	var err error

	if len(*typeFile) > 0 {
		err = readTypes(*typeFile)
		if err != nil {
			log.Fatalf("failed to read types: %s\n", err)
		}
	}

	if len(*o) != 0 {
		output, err = os.Create(*o)
		if err != nil {
			log.Fatalf("failed to create output file: %s", err)
		}
		defer output.Close()
	}

	if outputGo {
		fmt.Printf(`// This file is auto-generated by rpcc.
//
// Copyright (C) 2021 Markku Rossi.
//
// All rights reserved.
//

package ipc

`)
		err = goTypes()
		if err != nil {
			log.Fatalf("failed to generate types: %s", err)
		}
	}

	for _, arg := range flag.Args() {
		f, err := os.Open(arg)
		if err != nil {
			log.Fatalf("%s: %s\n", arg, err)
		}
		defer f.Close()
		header(arg)

		input := &Input{
			Reader: bufio.NewReader(f),
		}

		fmt.Fprintf(os.Stderr, "%s\n", arg)
		err = processFile(input)
		if err != nil {
			log.Fatalf("%s:%d: %s\n", arg, input.Line, err)
		}
	}

	if outputGo {
		err = goRPC()
		if err != nil {
			log.Fatalf("failed to generate RPC: %s", err)
		}
	}
}

// Input defines RPC input file.
type Input struct {
	Reader *bufio.Reader
	Line   int
}

// ReadLine reads the next input line.
func (i *Input) ReadLine() (string, error) {
	line, err := i.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	i.Line++
	return line, nil
}

func processFile(in *Input) error {
	var vMajor, vMinor, s0, s1, s2 int
	var functionName string
	var title string

	// Parse header.
	for {
		line, err := in.ReadLine()
		if err != nil {
			return err
		}
		print(line)
		m := reVersion.FindStringSubmatch(line)
		if m != nil {
			vMajori64, err := strconv.ParseInt(m[1], 10, 8)
			if err != nil {
				return err
			}
			vMajor = int(vMajori64) - 2

			vMinori64, err := strconv.ParseInt(m[2], 10, 8)
			if err != nil {
				return err
			}
			vMinor = int(vMinori64)
			continue
		}
		m = reSection.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s0i64, err := strconv.ParseInt(m[1], 10, 8)
		if err != nil {
			return err
		}
		s0 = int(s0i64)

		s1i64, err := strconv.ParseInt(m[2], 10, 8)
		if err != nil {
			return err
		}
		s1 = int(s1i64)

		title = strings.TrimSpace(m[3])
		break
	}
	if vMajor != vMajorLast || vMinor != vMinorLast {
		vMajorLast = vMajor
		vMinorLast = vMinor
		info("* Version %d.%d\n", vMajor+2, vMinor)
	}
	info("** %d.%d %s\n", s0, s1, title)

	// Process all functions
	for {
		line, err := in.ReadLine()
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
		m := reFunction.FindStringSubmatch(line)
		if m != nil {
			print(line)
			s2++
			functionName = m[1]
			info(" - %d.%d.%d %s\n", s0, s1, s2, functionName)
			continue
		}
		m = reSigStart.FindStringSubmatch(line)
		if m == nil {
			print(line)
			continue
		}
		// Process signature

		var session []Field
		var inputs []Field
		var outputs []Field
		var fieldSection *[]Field

		for {
			line, err = in.ReadLine()
			if err != nil {
				return err
			}
			if reSigEnd.FindStringSubmatch(line) != nil {
				// Signature processed
				break
			}
			m = reFieldSection.FindStringSubmatch(line)
			if m != nil {
				switch m[1] {
				case "Session":
					fieldSection = &session

				case "Inputs":
					fieldSection = &inputs

				case "Outputs":
					fieldSection = &outputs

				default:
					return fmt.Errorf("unknown field section: %s", m[1])
				}
				continue
			}

			m = reField.FindStringSubmatch(line)
			if m != nil {
				field, err := parseField(m[1], m[2])
				if err != nil {
					return err
				}
				if fieldSection == nil {
					return fmt.Errorf("field declaration without section")
				}
				*fieldSection = append(*fieldSection, field)
				continue
			}
		}

		msgType := ipc.NewType(vMajor, vMinor, s0, s1, s2)

		if outputC {
			print(`  VPBuffer buf;
  unsigned char *data;
  size_t len;
`)
			var depth int
			for _, input := range inputs {
				d, err := input.Depth()
				if err != nil {
					return err
				}
				if d > depth {
					depth = d
				}
			}
			if depth > 0 {
				print("  int")
				for i := 0; i < depth; i++ {
					if i == 0 {
						print(" ")
					} else {
						print(", ")
					}
					printf("%c", 'i'+i)
				}
				print(";\n")
			}

			switch len(session) {
			case 0:

			case 1:
				printf(`
  /* XXX lookup session by %s */
`,
					session[0].ElementName)

			default:
				return fmt.Errorf("multiple session variables")
			}

			printf(`
  vp_buffer_init(&buf);
  vp_buffer_add_uint32(&buf, 0x%08x);
  vp_buffer_add_space(&buf, 4);

`,
				int(msgType))

			for _, input := range inputs {
				err = input.Input(0)
				if err != nil {
					return err
				}
			}
			print(`
  data = vp_buffer_ptr(&buf);
  if (data == NULL)
    {
      vp_buffer_uninit(&buf);
      return CKR_HOST_MEMORY;
    }
  len = vp_buffer_len(&buf);
  VP_PUT_UINT32(data + 4, len - 8);

`)

			for idx, o := range outputs {
				info("  // Output %d: %#v\n", idx, o)
			}
			print("  VP_FUNCTION_NOT_SUPPORTED;\n")
		}

		if outputGo {
			goMessages = append(goMessages, GoMessage{
				Type:    msgType,
				Name:    functionName,
				Inputs:  inputs,
				Outputs: outputs,
			})
		}
	}
}

func goTypes() error {
	var arr []TypeInfo

	for _, t := range types {
		arr = append(arr, t)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Basic == arr[j].Basic {
			return arr[i].Name < arr[j].Name
		} else if arr[i].Basic {
			return true
		} else {
			return false
		}
	})
	for idx, t := range arr {
		if idx > 0 {
			fmt.Println()
		}
		if t.Basic {
			fmt.Printf(`// %s defines basic protocol type %s.
%s
`,
				GoTypeName(t.Name), t.Name, t.GoType())
		} else {
			fmt.Printf(`// %s defines compound protocol type %s.
%s
`,
				GoTypeName(t.Name), t.Name, t.GoType())
		}
	}

	return nil
}

var goMessages []GoMessage

// GoMessage defines a Go RPC message.
type GoMessage struct {
	Type    ipc.Type
	Name    string
	Inputs  []Field
	Outputs []Field
}

func goRPC() error {
	// Create RPC call argument and result types.
	for _, msg := range goMessages {
		goCallTypes(msg.Inputs, msg.Name, true)
		goCallTypes(msg.Outputs, msg.Name, false)
	}

	// Provider interface.
	fmt.Printf(`
// Provider defines the PKCS #11 provider interface.
type Provider interface {
`)
	for _, msg := range goMessages {
		goFunc := GoFuncName(msg.Name)
		fmt.Printf("\t%s(", goFunc)

		if len(msg.Inputs) > 0 {
			fmt.Printf("req *%sReq", goFunc)
		}

		fmt.Printf(") ")

		if len(msg.Outputs) > 0 {
			fmt.Printf("(*%sResp, error)", goFunc)
		} else {
			fmt.Printf("error")
		}
		fmt.Println()
	}
	fmt.Println("}")

	// Base provider.
	fmt.Printf(`
// Base provides a dummy implementation of the Provider interface.
type Base struct{}
`)
	for _, msg := range goMessages {
		goFunc := GoFuncName(msg.Name)
		fmt.Printf(`
// %s implements the Provider.%s().
func (b *Base) %s(`, goFunc, goFunc, goFunc)

		if len(msg.Inputs) > 0 {
			fmt.Printf("req *%sReq", goFunc)
		}

		fmt.Printf(") ")

		var result string
		if len(msg.Outputs) > 0 {
			fmt.Printf("(*%sResp, error)", goFunc)
			result = "nil, ErrFunctionNotSupported"
		} else {
			fmt.Printf("error")
			result = "ErrFunctionNotSupported"
		}
		fmt.Printf(` {
	return %s
}
`,
			result)
	}

	// RPC message names.
	fmt.Printf(`
var msgTypeNames = map[Type]string{
`)
	for _, msg := range goMessages {
		fmt.Printf("\t0x%08x: %q,\n", int(msg.Type), GoFuncName(msg.Name))
	}
	fmt.Printf("}\n")

	// Message dispatcher.
	fmt.Printf(`
func Dispatch(p Provider, msgType Type, req []byte) (CKRV, []byte) {
	resp, err := call(p, msgType, req)
	if err != nil {
		ckrv, ok := err.(CKRV)
		if ok {
			return ckrv, nil
		}
		return ErrFunctionNotSupported, nil
	}
	return ErrOk, resp
}

func call(p Provider, msgType Type, data []byte) ([]byte, error) {
	switch msgType {
`)

	for idx, msg := range goMessages {
		goFunc := GoFuncName(msg.Name)
		if idx > 0 {
			fmt.Println()
		}
		fmt.Printf("\tcase 0x%08x: // %s", int(msg.Type), goFunc)

		if len(msg.Inputs) > 0 {
			fmt.Printf(`
		var req %sReq
		if err := Unmarshal(data, &req); err != nil {
			return nil, err
		}`,
				goFunc)
			if len(msg.Outputs) > 0 {
				fmt.Printf(`
		resp, err := p.%s(&req)
		if err != nil {
			return nil, err
		}
		return Marshal(resp)
`,
					goFunc)
			} else {
				fmt.Printf(`
		return nil, p.%s(&req)
`,
					goFunc)
			}
		} else {
			if len(msg.Outputs) > 0 {
				fmt.Printf(`
		resp, err := p.%s()
		if err != nil {
			return nil, err
		}
		return Marshal(resp)
`,
					goFunc)
			} else {
				fmt.Printf(`
		return nil, p.%s()
`,
					goFunc)
			}
		}
	}

	fmt.Printf(`
	default:
		return nil, ErrFunctionNotSupported
	}
}
`)

	return nil
}

func goCallTypes(fields []Field, functionName string, req bool) {
	// XXX change to print to output file.
	if len(fields) == 0 {
		return
	}

	var max int
	for _, field := range fields {
		parts := strings.Split(field.GoType(), " ")
		if len(parts[0]) > max {
			max = len(parts[0])
		}
	}

	goFunc := GoFuncName(functionName)

	var suffix string
	var comment string

	if req {
		suffix = "Req"
		comment = "arguments"
	} else {
		suffix = "Resp"
		comment = "result"
	}

	fmt.Printf(`
// %s%s defines the %s of %s.
type %s%s struct {
`,
		goFunc, suffix, comment, functionName, goFunc, suffix)
	for _, field := range fields {
		parts := strings.Split(field.GoType(), " ")
		fmt.Printf("\t%s", parts[0])

		for i := len(parts[0]); i < max; i++ {
			fmt.Print(" ")
		}
		fmt.Printf(" %s\n", strings.Join(parts[1:], " "))
	}
	fmt.Printf("}\n")
}

func header(source string) {
	msg := fmt.Sprintf("/* This file is auto-generated from %s by rpcc. */\n",
		source)
	print(msg)
}

func info(format string, a ...interface{}) {
	if !printInfo {
		return
	}
	fmt.Printf(format, a...)
}

func debug(format string, a ...interface{}) {
	if !printDebug {
		return
	}
	fmt.Printf(format, a...)
}

func print(line string) {
	if !outputC {
		return
	}
	_, err := output.Write([]byte(line))
	if err != nil {
		log.Fatalf("write failed: %s", err)
	}
}

func printf(format string, a ...interface{}) {
	if !outputC {
		return
	}
	fmt.Fprintf(output, format, a...)
}
