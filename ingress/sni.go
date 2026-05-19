package ingress

import (
	"bufio"
	"encoding/binary"
	"errors"
	"strings"
)

func peekClientHello(br *bufio.Reader) (sni string, hello []byte, err error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", nil, err
	}
	if hdr[0] != 0x16 {
		return "", nil, errors.New("not TLS handshake")
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	total := 5 + recLen

	hello, err = br.Peek(total)
	if err != nil {
		return "", nil, err
	}

	data := hello[5:]
	if len(data) < 42 {
		return "", hello, errors.New("short ClientHello")
	}
	if data[0] != 0x01 {
		return "", hello, errors.New("not ClientHello")
	}

	i := 4
	if i+2+32 > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	i += 2 + 32

	if i >= len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	sidLen := int(data[i])
	i++
	if i+sidLen > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	i += sidLen

	if i+2 > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	csLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2
	if i+csLen > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	i += csLen

	if i >= len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	compLen := int(data[i])
	i++
	if i+compLen > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	i += compLen

	if i+2 > len(data) {
		return "", hello, errors.New("short ClientHello")
	}
	extLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2
	end := i + extLen
	if end > len(data) {
		return "", hello, errors.New("short ClientHello")
	}

	for i+4 <= end {
		typ := binary.BigEndian.Uint16(data[i:])
		sz := int(binary.BigEndian.Uint16(data[i+2:]))
		i += 4
		if i+sz > end {
			return "", hello, errors.New("bad extensions")
		}

		if typ == 0x00 {
			extEnd := i + sz
			if i+2 > extEnd {
				return "", hello, errors.New("bad sni extension")
			}
			listLen := int(binary.BigEndian.Uint16(data[i:]))
			listEnd := i + 2 + listLen
			if listEnd > extEnd {
				return "", hello, errors.New("bad sni extension")
			}
			j := i + 2
			for j+3 <= listEnd {
				nameType := data[j]
				nameLen := int(binary.BigEndian.Uint16(data[j+1:]))
				if nameType == 0 {
					if j+3+nameLen > listEnd {
						return "", hello, errors.New("bad sni extension")
					}
					sni = strings.ToLower(string(data[j+3 : j+3+nameLen]))
					return sni, hello, nil
				}
				j += 3 + nameLen
			}
		}
		i += sz
	}

	return "", hello, nil
}
