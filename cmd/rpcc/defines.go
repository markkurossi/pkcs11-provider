//
// Copyright (c) 2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"io"
	"log"
	"regexp"
	"strings"
)

var (
	reDefine = regexp.MustCompilePOSIX(`^#define[[:space:]]+([[:^space:]]+)[[:space:]]+(.*)$`)

	special = map[string]string{
		"AC":   "AC",
		"X":    "X",
		"Y":    "Y",
		"HW":   "HW",
		"MIDP": "MIDP",
		"CMS":  "CMS",
		"EC":   "EC",
		"ID":   "ID",
		"URL":  "URL",
	}
)

// Name defines Go-C name pair.
type Name struct {
	Go string
	C  string
}

func processDefines(in *Input) error {
	words := make(map[string]int)
	var names []Name

	for {
		line, err := in.ReadLine()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		m := reDefine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		value := strings.TrimSpace(m[2])

		var converted []string

		for _, word := range strings.Split(name, "_") {
			count := words[word]
			count++
			words[word] = count

			cvt, ok := special[word]
			if !ok {
				cvt = strings.Title(strings.ToLower(word))
			}
			converted = append(converted, cvt)
		}

		goName := strings.Join(converted, "")

		log.Printf("%-30s\t= %s\n", goName, value)
		names = append(names, Name{
			Go: goName,
			C:  name,
		})
	}

	if false {
		for k, v := range words {
			log.Printf("%s\t%d\n", k, v)
		}
	}

	for _, name := range names {
		log.Printf("%30s: %q,\n", name.Go, name.C)
	}

	return nil
}
