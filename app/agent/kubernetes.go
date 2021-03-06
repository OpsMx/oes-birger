package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/opsmx/grpc-bidir/pkg/tunnel"
	"golang.org/x/net/context"
)

func executeKubernetesRequest(dataflow chan *tunnel.ASEventWrapper, c *serverContextFields, req *tunnel.HttpRequest) {
	// TODO: A ServerCA is technically optional, but we might want to fail if it's not present...
	log.Printf("Running request %v", req)
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.insecure,
	}
	if c.serverCA != nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(c.serverCA)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	}
	if c.clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*c.clientCert}
	}
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}
	client := &http.Client{
		Transport: tr,
	}

	ctx, cancel := context.WithCancel(context.Background())

	registerCancelFunction(req.Id, cancel)
	defer unregisterCancelFunction(req.Id)

	httpRequest, err := http.NewRequestWithContext(ctx, req.Method, c.serverURL+req.URI, bytes.NewBuffer(req.Body))
	if err != nil {
		log.Printf("Failed to build request for %s to %s: %v", req.Method, c.serverURL+req.URI, err)
		dataflow <- makeBadGatewayResponse(req.Id, req.Target)
		return
	}
	for _, header := range req.Headers {
		for _, value := range header.Values {
			httpRequest.Header.Add(header.Name, value)
		}
	}
	if len(c.token) > 0 {
		httpRequest.Header.Set("Authorization", "Bearer "+c.token)
	}
	log.Printf("Sending HTTP request: %s to %v", req.Method, c.serverURL+req.URI)
	get, err := client.Do(httpRequest)
	if err != nil {
		log.Printf("Failed to execute request for %s to %s: %v", req.Method, c.serverURL+req.URI, err)
		dataflow <- makeBadGatewayResponse(req.Id, req.Target)
		return
	}

	// First, send the headers.
	resp := makeResponse(req.Id, req.Target, get)
	dataflow <- resp

	// Now, send one or more data packet.
	for {
		buf := make([]byte, 10240)
		n, err := get.Body.Read(buf)
		if n > 0 {
			resp := makeChunkedResponse(req.Id, req.Target, buf[:n])
			dataflow <- resp
		}
		if err == io.EOF {
			resp := makeChunkedResponse(req.Id, req.Target, emptyBytes)
			dataflow <- resp
			return
		}
		if err == context.Canceled {
			log.Printf("Context cancelled, request ID %s", req.Id)
			return
		}
		if err != nil {
			log.Printf("Got error on HTTP read: %v", err)
			// todo: send an error message somehow.  For now, just send EOF
			resp := makeChunkedResponse(req.Id, req.Target, emptyBytes)
			dataflow <- resp
			return
		}
	}
}
