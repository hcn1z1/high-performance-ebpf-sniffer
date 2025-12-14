package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

var greaseTable = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func ParseJA4(payload []byte) (string, error) {
	if len(payload) < 5 || payload[0] != 0x16 { return "", fmt.Errorf("not handshake") }
	handshakeData := payload[5:]
	if len(handshakeData) < 4 || handshakeData[0] != 0x01 { return "", fmt.Errorf("not clienthello") }

	offset := 4
	if len(handshakeData) < offset+2 { return "", fmt.Errorf("trunc") }
	recordVersion := binary.BigEndian.Uint16(handshakeData[offset : offset+2])
	// JA4 uses the record version for the version part, unless supported_versions ext is present (handled later)
	tlsVer := recordVersion
	offset += 34 // Ver(2) + Random(32)

	if len(handshakeData) < offset+1 { return "", fmt.Errorf("trunc") }
	offset += 1 + int(handshakeData[offset]) // SessionID

	if len(handshakeData) < offset+2 { return "", fmt.Errorf("trunc") }
	cipherLen := int(binary.BigEndian.Uint16(handshakeData[offset : offset+2]))
	offset += 2

	var ciphers []uint16
	for i := offset; i < offset+cipherLen; i += 2 {
		if i+2 > len(handshakeData) { break }
		val := binary.BigEndian.Uint16(handshakeData[i : i+2])
		if !greaseTable[val] { ciphers = append(ciphers, val) }
	}
	offset += cipherLen

	if len(handshakeData) < offset+1 { return "", fmt.Errorf("trunc") }
	offset += 1 + int(handshakeData[offset]) // Compression

	var extensions []uint16
	var sigAlgos []uint16
	sniPresent := false
	alpnVal := "00"

	if len(handshakeData) > offset+2 {
		extLen := int(binary.BigEndian.Uint16(handshakeData[offset : offset+2]))
		offset += 2
		end := offset + extLen
		if end > len(handshakeData) { end = len(handshakeData) }

		for offset < end {
			if offset+4 > len(handshakeData) { break }
			extType := binary.BigEndian.Uint16(handshakeData[offset : offset+2])
			eLen := int(binary.BigEndian.Uint16(handshakeData[offset+2 : offset+4]))
			offset += 4

			// Handle Specific Extensions for JA4_a
			if extType == 0x0000 { // SNI
				sniPresent = true
			} else if extType == 0x0010 { // ALPN
				if offset+2 <= len(handshakeData) {
					listLen := int(binary.BigEndian.Uint16(handshakeData[offset:offset+2]))
					if offset+2+listLen <= len(handshakeData) && listLen > 0 {
						// First protocol name
						pLen := int(handshakeData[offset+2])
						if pLen > 0 && offset+3+pLen <= len(handshakeData) {
							firstProto := handshakeData[offset+3 : offset+3+pLen]
							if len(firstProto) > 0 {
								// First and last char
								alpnVal = string([]byte{firstProto[0], firstProto[len(firstProto)-1]})
							}
						}
					}
				}
			} else if extType == 0x002b { // Supported Versions
				// Simplified: look for highest version in the list
				if offset+1 <= len(handshakeData) {
					verListLen := int(handshakeData[offset])
					for v := 0; v < verListLen; v += 2 {
						if offset+1+v+2 <= len(handshakeData) {
							vVal := binary.BigEndian.Uint16(handshakeData[offset+1+v : offset+1+v+2])
							if !greaseTable[vVal] {
								// JA4 logic: if 1.3 (0x0304) is present, use it.
								if vVal == 0x0304 { tlsVer = 0x0304 } else if vVal == 0x0303 && tlsVer < 0x0303 { tlsVer = 0x0303 }
							}
						}
					}
				}
			} else if extType == 0x000d { // Signature Algorithms
				if offset+2 <= len(handshakeData) {
					saLen := int(binary.BigEndian.Uint16(handshakeData[offset:offset+2]))
					for s := 0; s < saLen; s+=2 {
						if offset+2+s+2 <= len(handshakeData) {
							sig := binary.BigEndian.Uint16(handshakeData[offset+2+s : offset+2+s+2])
							sigAlgos = append(sigAlgos, sig)
						}
					}
				}
			}

			// JA4 Excludes SNI (0x0000) and ALPN (0x0010) from the extension list hash, but COUNTS them.
			// Wait, spec says: "Ignore the SNI extension (0000) and the ALPN extension (0010) as we've already captured them in the a section... These values are NOT included in the extension count."
			if !greaseTable[extType] && extType != 0x0000 && extType != 0x0010 {
				extensions = append(extensions, extType)
			}

			offset += eLen
		}
	}

	// Construct JA4_a
	// [Proto][Ver][SNI][CipherCnt][ExtCnt][ALPN]
	proto := "t"
	verStr := "00"
	switch tlsVer {
	case 0x0304: verStr = "13"
	case 0x0303: verStr = "12"
	case 0x0302: verStr = "11"
	case 0x0301: verStr = "10"
	}
	sniStr := "i"
	if sniPresent { sniStr = "d" }

	ja4_a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, verStr, sniStr, len(ciphers), len(extensions), alpnVal)

	// Construct JA4_b: SHA256(Sorted Ciphers)
	// Sort ciphers
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	var cipherStrings []string
	for _, c := range ciphers { cipherStrings = append(cipherStrings, fmt.Sprintf("%04x", c)) }
	cipherContent := strings.Join(cipherStrings, ",")
	bHash := sha256.Sum256([]byte(cipherContent))
	ja4_b := hex.EncodeToString(bHash[:])[:12]

	// Construct JA4_c: SHA256(Sorted Extensions + "_" + Signature Algorithms)
	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	var extStrings []string
	for _, e := range extensions { extStrings = append(extStrings, fmt.Sprintf("%04x", e)) }
	extContent := strings.Join(extStrings, ",")

	var sigStrings []string
	for _, s := range sigAlgos { sigStrings = append(sigStrings, fmt.Sprintf("%04x", s)) }
	sigContent := strings.Join(sigStrings, ",")

	cRaw := extContent
	if len(sigAlgos) > 0 {
		cRaw = cRaw + "_" + sigContent
	}

	cHash := sha256.Sum256([]byte(cRaw))
	ja4_c := hex.EncodeToString(cHash[:])[:12]

	return fmt.Sprintf("%s_%s_%s", ja4_a, ja4_b, ja4_c), nil
}
