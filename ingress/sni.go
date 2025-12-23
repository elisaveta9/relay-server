package ingress

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

func peekClientHello(r io.Reader) (sni string, hello []byte, err error) {
	br := bufio.NewReader(r)

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
	if data[0] != 0x01 {
		return "", hello, errors.New("not ClientHello")
	}

	i := 4
	i += 2 + 32

	sidLen := int(data[i])
	i += 1 + sidLen

	csLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2 + csLen

	compLen := int(data[i])
	i += 1 + compLen

	extLen := int(binary.BigEndian.Uint16(data[i:]))
	i += 2
	end := i + extLen

	for i+4 <= end {
		typ := binary.BigEndian.Uint16(data[i:])
		sz := int(binary.BigEndian.Uint16(data[i+2:]))
		i += 4

		if typ == 0x00 {
			l := int(binary.BigEndian.Uint16(data[i:]))
			j := i + 2
			for j+3 < i+l {
				nameType := data[j]
				nameLen := int(binary.BigEndian.Uint16(data[j+1:]))
				if nameType == 0 {
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
