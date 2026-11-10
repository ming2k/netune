// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s https://host:port/path", os.Args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transport := &webtransport.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		Config: &webtransport.Config{
			MaxIncomingStreams:    100,
			MaxIncomingUniStreams: 100,
			MaxIncomingData:       16 * 1024 * 1024,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	defer transport.Close()

	response, session, err := transport.Dial(ctx, os.Args[1], nil)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	fmt.Printf("STATUS=%d\n", response.StatusCode)
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write([]byte("hello from go")); err != nil {
		log.Fatalf("write: %v", err)
	}
	if err := stream.Close(); err != nil {
		log.Fatalf("close write side: %v", err)
	}
	body, err := io.ReadAll(stream)
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	fmt.Printf("GOT=%s\n", body)
	if string(body) != "pong from netune" {
		log.Fatalf("unexpected echo: %q", body)
	}

	uni, err := session.OpenUniStreamSync(ctx)
	if err != nil {
		log.Fatalf("open uni stream: %v", err)
	}
	if _, err := uni.Write([]byte("hello uni from go")); err != nil {
		log.Fatalf("write uni: %v", err)
	}
	if err := uni.Close(); err != nil {
		log.Fatalf("close uni: %v", err)
	}
	incoming, err := session.AcceptUniStream(ctx)
	if err != nil {
		log.Fatalf("accept uni stream: %v", err)
	}
	uniBody, err := io.ReadAll(incoming)
	if err != nil {
		log.Fatalf("read uni: %v", err)
	}
	fmt.Printf("UNI=%s\n", uniBody)
	if string(uniBody) != "pong uni from netune" {
		log.Fatalf("unexpected uni echo: %q", uniBody)
	}

	if err := session.SendDatagram([]byte("hello datagram from go")); err != nil {
		log.Fatalf("send datagram: %v", err)
	}
	datagram, err := session.ReceiveDatagram(ctx)
	if err != nil {
		log.Fatalf("receive datagram: %v", err)
	}
	fmt.Printf("DATAGRAM=%s\n", datagram)
	if string(datagram) != "pong datagram from netune" {
		log.Fatalf("unexpected datagram echo: %q", datagram)
	}
}
