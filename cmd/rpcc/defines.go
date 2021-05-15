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
		"AC":        "AC",
		"X":         "X",
		"Y":         "Y",
		"HW":        "HW",
		"MIDP":      "MIDP",
		"CMS":       "CMS",
		"EC":        "EC",
		"ECDSA":     "",
		"ECDH1":     "",
		"ECDH":      "",
		"ECMQV":     "",
		"ID":        "ID",
		"URL":       "URL",
		"RSA":       "RSA",
		"DSA":       "DSA",
		"DH":        "DH",
		"ECC":       "",
		"MQV":       "MQV",
		"PKCS":      "PKCS",
		"PKCS5":     "",
		"OAEP":      "",
		"PSS":       "PSS",
		"MD2":       "MD2",
		"MD5":       "MD5",
		"RIPEMD128": "RIPEMD128",
		"RIPEMD160": "RIPEMD160",
		"SHA":       "",
		"SHA1":      "",
		"SHA3":      "",
		"SHA224":    "",
		"SHA256":    "",
		"SHA384":    "",
		"SHA512":    "",
		"HMAC":      "HMAC",
		"CHACHA20":  "ChaCha20",
		"SALSA20":   "Salsa20",
		"GOSTR3410": "GostR3410",
		"GOST28147": "Gost28147",
		"POLY1305":  "Poly1305",
		"ECB":       "",
		"EDE":       "",
		"TPM":       "",
		"ECB64":     "",
		"ECB128":    "",
		"CBC":       "",
		"CBC64":     "",
		"CBC128":    "",
		"CTR":       "",
		"GCM":       "",
		"CCM":       "",
		"CMAC":      "",
		"XCBC":      "",
		"X3DH":      "",
		"XEDDSA":    "",
		"EDDSA":     "",
		"SP800":     "",
		"X2RATCHET": "X2Ratchet",
		"GMAC":      "",
		"XTS":       "",
		"CTS":       "",
		"OFB":       "",
		"CFB":       "",
		"KWP":       "",
		"MAC":       "MAC",
		"RC2":       "RC2",
		"RC4":       "RC4",
		"RC5":       "",
		"DES":       "",
		"DES2":      "",
		"DES3":      "",
		"CDMF":      "",
		"OFB64":     "",
		"OFB8":      "",
		"CFB1":      "",
		"CFB8":      "",
		"CFB16":     "",
		"CFB32":     "",
		"CFB64":     "",
		"CFB128":    "",
		"SECURID":   "SecurID",
		"RELAYX":    "RelayX",
		"HOTP":      "",
		"ACTI":      "",
		"CAST":      "",
		"CAST3":     "",
		"CAST5":     "",
		"CAST128":   "",
		"IDEA":      "",
		"XOR":       "",
		"SSL3":      "",
		"TLS":       "",
		"TLS10":     "",
		"TLS12":     "",
		"WTLS":      "",
		"PBE":       "",
		"PBA":       "",
		"PBKD2":     "",
		"PRF":       "",
		"KDF":       "",
		"HKDF":      "",
		"LYNKS":     "",
		"KIP":       "",
		"AES":       "",
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
			if ok {
				if len(cvt) == 0 {
					cvt = word
				}
			} else {
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
