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

func main() {
	log.SetFlags(0)
	flag.Parse()

	fmt.Printf("PKCS #11 RPC Compiler\n")

	for _, arg := range flag.Args() {
		f, err := os.Open(arg)
		if err != nil {
			log.Fatalf("%s: %s\n", arg, err)
		}
		defer f.Close()
		err = processFile(f)
		if err != nil {
			log.Fatalf("%s: %s\n", arg, err)
		}
	}
}

var (
	reHeader   = regexp.MustCompilePOSIX(`/\*\*[[:space:]]+([[:digit:]]+)\.([[:digit:]]+)[[:space:]]*([^\*]+)`)
	reFunction = regexp.MustCompilePOSIX(`^(C_[a-zA-Z0-9_]+)`)
)

func processFile(in io.Reader) error {
	reader := bufio.NewReader(in)

	var v0, v1, v2 uint8

	// Find header line.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		m := reHeader.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v0i64, err := strconv.ParseInt(m[1], 10, 8)
		if err != nil {
			return err
		}
		v0 = uint8(v0i64)

		v1i64, err := strconv.ParseInt(m[2], 10, 8)
		if err != nil {
			return err
		}
		v1 = uint8(v1i64)

		title := strings.TrimSpace(m[3])

		fmt.Printf("%d.%d %s\n", v0, v1, title)
		break
	}

	// Process all functions
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
		m := reFunction.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v2++

		name := m[1]
		fmt.Printf(" - %d.%d.%d %s\n", v0, v1, v2, name)
	}
}
