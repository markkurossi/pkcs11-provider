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
	"strconv"
	"strings"
)

var (
	reVersion  = regexp.MustCompilePOSIX(`/\*\*[[:space:]]+Version:[[:space:]]+([[:digit:]]+)\.([[:digit:]]+)`)
	reSection  = regexp.MustCompilePOSIX(`/\*\*[[:space:]]+Section:[[:space:]]+([[:digit:]]+)\.([[:digit:]]+)[[:space:]]*([^\*]+)`)
	reFunction = regexp.MustCompilePOSIX(`^(C_[a-zA-Z0-9_]+)`)
	reSigStart = regexp.MustCompilePOSIX(`^[[:space:]]*/\*\*[[:space:]]*$`)
	reSigEnd   = regexp.MustCompilePOSIX(`^[[:space:]]*\*/[[:space:]]*$`)

	vMajorLast uint8
	vMinorLast uint8

	output   io.WriteCloser = os.Stdout
	outputC  bool
	outputGo bool
)

func main() {
	log.SetFlags(0)
	flag.BoolVar(&outputC, "c", false, "generate C code")
	o := flag.String("o", "", "output file name")
	flag.Parse()

	fmt.Printf("PKCS #11 RPC Compiler\n")

	var err error

	if len(*o) != 0 {
		output, err = os.Create(*o)
		if err != nil {
			log.Fatalf("failed to create output file: %s", err)
		}
		defer output.Close()
	}

	for _, arg := range flag.Args() {
		f, err := os.Open(arg)
		if err != nil {
			log.Fatalf("%s: %s\n", arg, err)
		}
		defer f.Close()
		header(arg)
		err = processFile(f)
		if err != nil {
			log.Fatalf("%s: %s\n", arg, err)
		}
	}
}

func processFile(in io.Reader) error {
	reader := bufio.NewReader(in)

	var vMajor, vMinor, s0, s1, s2 uint8
	var title string

	// Parse header.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		passThrough(line)
		m := reVersion.FindStringSubmatch(line)
		if m != nil {
			vMajori64, err := strconv.ParseInt(m[1], 10, 8)
			if err != nil {
				return err
			}
			vMajor = uint8(vMajori64) - 2

			vMinori64, err := strconv.ParseInt(m[2], 10, 8)
			if err != nil {
				return err
			}
			vMinor = uint8(vMinori64)
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
		s0 = uint8(s0i64)

		s1i64, err := strconv.ParseInt(m[2], 10, 8)
		if err != nil {
			return err
		}
		s1 = uint8(s1i64)

		title = strings.TrimSpace(m[3])
		break
	}
	if vMajor != vMajorLast || vMinor != vMinorLast {
		vMajorLast = vMajor
		vMinorLast = vMinor
		fmt.Printf("* Version %d.%d\n", vMajor+2, vMinor)
	}
	fmt.Printf("** %d.%d %s\n", s0, s1, title)

	// Process all functions
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
		passThrough(line)
		m := reFunction.FindStringSubmatch(line)
		if m != nil {
			s2++
			name := m[1]
			fmt.Printf(" - %d.%d.%d %s\n", s0, s1, s2, name)
			continue
		}
		m = reSigStart.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// Process signature
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				return err
			}
			passThrough(line)
			if reSigEnd.FindStringSubmatch(line) != nil {
				// Signature processed
				break
			}
		}
		passThrough("  VP_FUNCTION_NOT_SUPPORTED;\n")
	}
}

func header(source string) {
	msg := fmt.Sprintf("/* This file is auto-generated from %s by rpcc. */\n",
		source)
	passThrough(msg)
}

func passThrough(line string) {
	if !outputC {
		return
	}
	_, err := output.Write([]byte(line))
	if err != nil {
		log.Fatalf("write failed: %s", err)
	}
}
