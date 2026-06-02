package ingress

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	tlsRecordHeaderLen = 5
	maxTLSRecordLen    = 18 * 1024
	maxClientHelloLen  = 64 * 1024
)

func peekClientHello(br *bufio.Reader) (sni string, hello []byte, err error) {
	var handshake []byte
	offset := 0

	for {
		hdr, err := br.Peek(offset + tlsRecordHeaderLen)
		if err != nil {
			return "", nil, err
		}

		recordHeader := hdr[offset : offset+tlsRecordHeaderLen]
		if recordHeader[0] != 0x16 {
			return "", nil, errors.New("not TLS handshake")
		}

		recLen := int(binary.BigEndian.Uint16(recordHeader[3:5]))
		if recLen <= 0 || recLen > maxTLSRecordLen {
			return "", nil, fmt.Errorf("invalid TLS record length: %d", recLen)
		}

		recordEnd := offset + tlsRecordHeaderLen + recLen
		records, err := br.Peek(recordEnd)
		if err != nil {
			return "", nil, err
		}

		handshake = append(handshake, records[offset+tlsRecordHeaderLen:recordEnd]...)
		if len(handshake) > maxClientHelloLen {
			return "", nil, errors.New("ClientHello too large")
		}

		if len(handshake) >= 4 {
			if handshake[0] != 0x01 {
				return "", records[:recordEnd], errors.New("not ClientHello")
			}

			clientHelloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if clientHelloLen <= 0 || clientHelloLen+4 > maxClientHelloLen {
				return "", records[:recordEnd], fmt.Errorf("invalid ClientHello length: %d", clientHelloLen)
			}

			if len(handshake) >= clientHelloLen+4 {
				sni, err := parseClientHelloSNI(handshake[:clientHelloLen+4])
				return sni, records[:recordEnd], err
			}
		}

		offset = recordEnd
		if offset > maxClientHelloLen {
			return "", nil, errors.New("ClientHello records too large")
		}
	}
}

func parseClientHelloSNI(data []byte) (string, error) {
	if len(data) < 42 {
		return "", errors.New("short ClientHello")
	}
	if data[0] != 0x01 {
		return "", errors.New("not ClientHello")
	}

	i := 4
	if i+2+32 > len(data) {
		return "", errors.New("short ClientHello")
	}
	i += 2 + 32

	if i >= len(data) {
		return "", errors.New("short ClientHello")
	}
	sidLen := int(data[i])
	i++
	if i+sidLen > len(data) {
		return "", errors.New("short ClientHello")
	}
	i += sidLen

	if i+2 > len(data) {
		return "", errors.New("short ClientHello")
	}
	csLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2
	if i+csLen > len(data) {
		return "", errors.New("short ClientHello")
	}
	i += csLen

	if i >= len(data) {
		return "", errors.New("short ClientHello")
	}
	compLen := int(data[i])
	i++
	if i+compLen > len(data) {
		return "", errors.New("short ClientHello")
	}
	i += compLen

	if i+2 > len(data) {
		return "", errors.New("short ClientHello")
	}
	extLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2
	end := i + extLen
	if end > len(data) {
		return "", errors.New("short ClientHello")
	}

	for i+4 <= end {
		typ := binary.BigEndian.Uint16(data[i:])
		sz := int(binary.BigEndian.Uint16(data[i+2:]))
		i += 4
		if i+sz > end {
			return "", errors.New("bad extensions")
		}

		if typ == 0x00 {
			extEnd := i + sz
			if i+2 > extEnd {
				return "", errors.New("bad sni extension")
			}
			listLen := int(binary.BigEndian.Uint16(data[i:]))
			listEnd := i + 2 + listLen
			if listEnd > extEnd {
				return "", errors.New("bad sni extension")
			}
			j := i + 2
			for j+3 <= listEnd {
				nameType := data[j]
				nameLen := int(binary.BigEndian.Uint16(data[j+1:]))
				if nameType == 0 {
					if j+3+nameLen > listEnd {
						return "", errors.New("bad sni extension")
					}
					return strings.ToLower(string(data[j+3 : j+3+nameLen])), nil
				}
				j += 3 + nameLen
			}
		}
		i += sz
	}

	return "", nil
}
