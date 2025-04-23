package server

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"proxy/internal/repository"
	"strconv"
	"strings"
)

func (s *ProxyServer) handleRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.repo.GetListOfRequests()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Requests</h1><ul>")
	for _, req := range requests {
		fmt.Fprintf(w, "<li><a href='/api/requests/%d'>%s %s</a></li>", req.ID, req.Method, req.URL)
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

func (s *ProxyServer) handleSingleRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	exists, req, err := s.repo.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Request %d</h1>", id)
	fmt.Fprintf(w, "<p><b>Method:</b> %s</p>", req.Method)
	fmt.Fprintf(w, "<p><b>URL:</b> %s</p>", req.URL)
	fmt.Fprintf(w, "<p><b>GET Params:</b> %v</p>", req.GetParams)
	fmt.Fprintf(w, "<p><b>POST Params:</b> %v</p>", req.PostParams)
	fmt.Fprintf(w, "<p><b>Headers:</b> %v</p>", req.Headers)
	fmt.Fprintf(w, "<p><b>Cookies:</b> %v</p>", req.Cookies)
	fmt.Fprintf(w, "<p><b>Body:</b> %s</p>", req.Body)
	fmt.Fprintf(w, "</body></html>")
}

func (s *ProxyServer) handleRepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	exists, req, err := s.repo.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusInternalServerError)
		return
	}

	newReq, err := http.NewRequest(req.Method, parsedURL.String(), strings.NewReader(req.Body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range req.Headers {
		newReq.Header.Set(k, v)
	}

	for k, v := range req.Cookies {
		newReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	client := &http.Client{}
	resp, err := client.Do(newReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": resp.StatusCode,
		"body":   string(body),
	})
}

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
	req := p.parseRequest(r)
	if err := p.repo.WriteRequest(req); err != nil {
		log.Println(err)
	}

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

func (s *ProxyServer) parseRequest(r *http.Request) *repository.Request {
	req := &repository.Request{
		Method:    r.Method,
		URL:       r.URL.String(),
		GetParams: make(map[string]string),
		Headers:   make(map[string]string),
		Cookies:   make(map[string]string),
	}

	for k, v := range r.URL.Query() {
		req.GetParams[k] = strings.Join(v, ",")
	}

	for k, v := range r.Header {
		if k == "Cookie" {
			for _, cookie := range r.Cookies() {
				req.Cookies[cookie.Name] = cookie.Value
			}
		} else {
			req.Headers[k] = strings.Join(v, ",")
		}
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			r.ParseForm()
			req.PostParams = make(map[string]string)
			for k, v := range r.PostForm {
				req.PostParams[k] = strings.Join(v, ",")
			}
		} else {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			req.Body = string(body)
		}
	}

	return req
}

func (s *ProxyServer) parseResponse(resp *http.Response, reqID int) *repository.Response {
	response := &repository.Response{
		Code:      resp.StatusCode,
		Message:   resp.Status,
		Headers:   make(map[string]string),
		IDRequest: reqID,
	}

	for k, v := range resp.Header {
		response.Headers[k] = strings.Join(v, ",")
	}

	var body []byte
	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		reader, _ := gzip.NewReader(resp.Body)
		body, _ = io.ReadAll(reader)
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
	} else {
		body, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
	}
	response.Body = string(body)

	return response
}
