package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
)

func (p *ProxyServer) handlerHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := new(http.Request)
	*outReq = *r

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func (p *ProxyServer) handlerHTTPS(w http.ResponseWriter, r *http.Request) {
	fmt.Println("get query", r.Host, r.Method, r.URL)
	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	cert, err := p.getCert(host)
	if err != nil {
		log.Printf("Failed to generate cert for %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake error with client: %v", err)
		tlsClientConn.Close()
		return
	}

	upstreamConn, err := tls.Dial("tcp", r.Host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("Failed to connect to upstream %s: %v", r.Host, err)
		tlsClientConn.Close()
		return
	}

	go p.pipeConnections(tlsClientConn, upstreamConn)
}

func (p *ProxyServer) pipeConnections(clientConn, upstreamConn net.Conn) {
	defer clientConn.Close()
	defer upstreamConn.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()

	<-done
	<-done
}
