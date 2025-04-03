package server

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func (s *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("HTTP request:", r.Method, r.URL)

	r.Header.Del("Proxy-Connection")

	targetURL := r.URL
	if r.URL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if r.URL.Host == "" {
		targetURL.Host = r.Host
	}

	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header = r.Header
	req.Host = r.Host
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("Error copying response body:", err)
	}
}

func (s *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Println("HTTPS CONNECT request:", r.Host)

	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go s.tunnel(clientConn, targetConn)
}

func (s *ProxyServer) tunnel(clientConn net.Conn, targetConn net.Conn) {
	defer clientConn.Close()
	defer targetConn.Close()

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}
