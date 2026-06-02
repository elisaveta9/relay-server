package ingress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestPeekClientHelloHandlesFragmentedHandshake(t *testing.T) {
	record := captureClientHelloRecord(t, "X.Go.Dev")
	fragmented := fragmentTLSHandshakeRecord(t, record, 16)

	sni, hello, err := peekClientHello(bufio.NewReader(bytes.NewReader(fragmented)))
	if err != nil {
		t.Fatalf("peekClientHello returned error: %v", err)
	}
	if sni != "x.go.dev" {
		t.Fatalf("sni = %q, want %q", sni, "x.go.dev")
	}
	if !bytes.Equal(hello, fragmented) {
		t.Fatalf("hello bytes were not preserved")
	}
}

func captureClientHelloRecord(t *testing.T, serverName string) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer closeTestConn(t, clientConn, "client pipe")
	defer closeTestConn(t, serverConn, "server pipe")

	errCh := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		})
		errCh <- tlsConn.Handshake()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	hdr := make([]byte, tlsRecordHeaderLen)
	if _, err := io.ReadFull(serverConn, hdr); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	record := make([]byte, tlsRecordHeaderLen+recLen)
	copy(record, hdr)
	if _, err := io.ReadFull(serverConn, record[tlsRecordHeaderLen:]); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client pipe: %v", err)
	}
	if err := <-errCh; err == nil {
		t.Fatal("client handshake unexpectedly completed")
	}

	return record
}

func closeTestConn(t *testing.T, conn net.Conn, name string) {
	t.Helper()

	if err := conn.Close(); err != nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("close %s: %v", name, err)
	}
}

func fragmentTLSHandshakeRecord(t *testing.T, record []byte, split int) []byte {
	t.Helper()

	if len(record) < tlsRecordHeaderLen || record[0] != 0x16 {
		t.Fatalf("not a TLS handshake record")
	}

	payload := record[tlsRecordHeaderLen:]
	if split <= 0 || split >= len(payload) {
		t.Fatalf("bad split %d for payload length %d", split, len(payload))
	}

	firstHeader := append([]byte(nil), record[:tlsRecordHeaderLen]...)
	binary.BigEndian.PutUint16(firstHeader[3:5], uint16(split))

	secondHeader := append([]byte(nil), record[:tlsRecordHeaderLen]...)
	binary.BigEndian.PutUint16(secondHeader[3:5], uint16(len(payload)-split))

	fragmented := make([]byte, 0, len(record)+tlsRecordHeaderLen)
	fragmented = append(fragmented, firstHeader...)
	fragmented = append(fragmented, payload[:split]...)
	fragmented = append(fragmented, secondHeader...)
	fragmented = append(fragmented, payload[split:]...)
	return fragmented
}
