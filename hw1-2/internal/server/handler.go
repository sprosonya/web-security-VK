package server

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/andybalholm/brotli"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"net/url"
	"proxy/internal/repository"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
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
		http.Error(w, `{"error": "Invalid ID"}`, http.StatusBadRequest)
		return
	}

	exists, req, err := s.repo.GetByID(id)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, `{"error": "Request not found"}`, http.StatusNotFound)
		return
	}

	targetURL := req.URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, `{"error": "Invalid URL: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	newReq, err := http.NewRequest(req.Method, parsedURL.String(), bodyReader)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	for k, v := range req.Headers {
		newReq.Header.Set(k, v)
	}

	for k, v := range req.Cookies {
		newReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Не следовать редиректам
		},
	}

	resp, err := client.Do(newReq)
	if err != nil {
		http.Error(w, `{"error": "Request failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error": "Failed to read response: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":     resp.StatusCode,
		"statusText": resp.Status,
		"headers":    resp.Header,
		"body":       string(body),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func (p *ProxyServer) handlerHTTP(w http.ResponseWriter, r *http.Request) {
	req := p.parseRequest(r)
	if err := p.repo.WriteRequest(req); err != nil {
		log.Println(err)
	}
	outReq := new(http.Request)
	*outReq = *r

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	respStruct := p.parseResponse(resp, req.ID)
	if err := p.repo.WriteResponse(respStruct); err != nil {
		log.Println(err)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func (p *ProxyServer) handlerHTTPS(w http.ResponseWriter, r *http.Request) {
	fmt.Println("AAAAAA")
	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("Error writing 200 OK: %v", err)
		return
	}

	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	cert, err := p.getCert(strings.Split(host, ":")[0])
	if err != nil {
		log.Printf("Get certificate error: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		if !isExpectedTLSHandshakeError(err) {
			log.Printf("TLS handshake error: %v", err)
		}
		return
	}

	bufReader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		if !isExpectedReadError(err) {
			log.Printf("Error reading request: %v", err)
		}
		return
	}

	if req.URL.Host == "" {
		req.URL.Host = r.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	fixContentLength(req)

	httpReq := p.parseRequest(req)
	if err := p.repo.WriteRequest(httpReq); err != nil {
		log.Printf("Error saving request: %v", err)
	}

	targetConn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("Error dialing target: %v", err)
		return
	}
	defer targetConn.Close()

	req.Header.Del("Accept-Encoding")
	req.Header.Del("Keep-Alive")

	if err := fixRequest(req); err != nil {
		log.Printf("Error fixing request: %v", err)
		return
	}

	if err := req.Write(targetConn); err != nil {
		log.Printf("Error writing to target: %v", err)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), req)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return
	}
	defer resp.Body.Close()

	httpResp := p.parseResponse(resp, httpReq.ID)
	if err := p.repo.WriteResponse(httpResp); err != nil {
		log.Printf("Error saving response: %v", err)
	}

	if err := resp.Write(tlsConn); err != nil {
		log.Printf("Error writing response to client: %v", err)
	}
}

func fixContentLength(req *http.Request) {
	if req.Body == nil || req.Body == http.NoBody {
		req.ContentLength = 0
		req.Header.Del("Content-Length")
	}
}

func fixRequest(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		req.ContentLength = 0
		req.Header.Del("Content-Length")
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body.Close()

	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))

	return nil
}

func isExpectedTLSHandshakeError(err error) bool {
	return err == io.EOF ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "reset by peer")
}

func isExpectedReadError(err error) bool {
	return isExpectedTLSHandshakeError(err) ||
		strings.Contains(err.Error(), "malformed HTTP")
}

func (s *ProxyServer) parseResponse(resp *http.Response, reqID int) *repository.Response {
	response := &repository.Response{
		Code:      resp.StatusCode,
		Message:   resp.Status,
		Headers:   make(map[string]string),
		IDRequest: reqID,
	}

	for k, v := range resp.Header {
		if !strings.EqualFold(k, "Content-Encoding") {
			response.Headers[k] = strings.Join(v, ",")
		}
	}

	var body []byte
	var err error

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("Gzip decompression error: %v", err)
			return response
		}
		body, err = io.ReadAll(reader)
		reader.Close()
	case "deflate":
		reader := flate.NewReader(resp.Body)
		body, err = io.ReadAll(reader)
		reader.Close()
	case "br":
		reader := brotli.NewReader(resp.Body)
		body, err = io.ReadAll(reader)
	default:
		body, err = io.ReadAll(resp.Body)
	}

	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return response
	}

	if !utf8.Valid(body) {
		response.Body = base64.StdEncoding.EncodeToString(body)
		response.IsBase64 = true
	} else {
		response.Body = string(body)
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return response
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

func (p *ProxyServer) handleScanRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, `{"error": "Invalid ID"}`, http.StatusBadRequest)
		return
	}

	exists, originalReq, err := p.repo.GetByID(id)
	if err != nil {
		http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, `{"error": "Request not found"}`, http.StatusNotFound)
		return
	}

	report := p.scanRequestForVulnerabilities(originalReq)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func (p *ProxyServer) scanRequestForVulnerabilities(originalReq *repository.Request) map[string]interface{} {
	vulnerabilities := make([]map[string]string, 0)

	injectionTests := []struct {
		payload     string
		description string
	}{
		{`;cat /etc/passwd;`, "Command Injection через ;"},
		{`|cat /etc/passwd|`, "Command Injection через |"},
		{"`cat /etc/passwd`", "Command Injection через backticks"},
		{"$(cat /etc/passwd)", "Command Injection через $()"},
	}

	for param := range originalReq.GetParams {
		for _, test := range injectionTests {
			modifiedReq := p.cloneRequest(originalReq)
			modifiedReq.GetParams[param] = test.payload

			resp, err := p.sendModifiedRequest(modifiedReq)
			if err != nil {
				continue
			}

			if p.isResponseVulnerable(resp) {
				vulnerabilities = append(vulnerabilities, map[string]string{
					"type":        "Command Injection",
					"parameter":   "GET:" + param,
					"payload":     test.payload,
					"description": test.description,
					"severity":    "High",
				})
				break
			}
		}
	}

	for param := range originalReq.PostParams {
		for _, test := range injectionTests {
			modifiedReq := p.cloneRequest(originalReq)
			modifiedReq.PostParams[param] = test.payload

			resp, err := p.sendModifiedRequest(modifiedReq)
			if err != nil {
				continue
			}

			if p.isResponseVulnerable(resp) {
				vulnerabilities = append(vulnerabilities, map[string]string{
					"type":        "Command Injection",
					"parameter":   "POST:" + param,
					"payload":     test.payload,
					"description": test.description,
					"severity":    "High",
				})
				break
			}
		}
	}

	for name := range originalReq.Cookies {
		for _, test := range injectionTests {
			modifiedReq := p.cloneRequest(originalReq)
			modifiedReq.Cookies[name] = test.payload

			resp, err := p.sendModifiedRequest(modifiedReq)
			if err != nil {
				continue
			}

			if p.isResponseVulnerable(resp) {
				vulnerabilities = append(vulnerabilities, map[string]string{
					"type":        "Command Injection",
					"parameter":   "COOKIE:" + name,
					"payload":     test.payload,
					"description": test.description,
					"severity":    "High",
				})
				break
			}
		}
	}

	for name := range originalReq.Headers {
		for _, test := range injectionTests {
			modifiedReq := p.cloneRequest(originalReq)
			modifiedReq.Headers[name] = test.payload

			resp, err := p.sendModifiedRequest(modifiedReq)
			if err != nil {
				continue
			}

			if p.isResponseVulnerable(resp) {
				vulnerabilities = append(vulnerabilities, map[string]string{
					"type":        "Command Injection",
					"parameter":   "HEADER:" + name,
					"payload":     test.payload,
					"description": test.description,
					"severity":    "High",
				})
				break
			}
		}
	}

	if originalReq.Body != "" {
		for _, test := range injectionTests {
			modifiedReq := p.cloneRequest(originalReq)
			modifiedReq.Body = test.payload

			resp, err := p.sendModifiedRequest(modifiedReq)
			if err != nil {
				continue
			}

			if p.isResponseVulnerable(resp) {
				vulnerabilities = append(vulnerabilities, map[string]string{
					"type":        "Command Injection",
					"parameter":   "BODY",
					"payload":     test.payload,
					"description": test.description,
					"severity":    "High",
				})
				break
			}
		}
	}

	return map[string]interface{}{
		"request_id":            originalReq.ID,
		"request_url":           originalReq.URL,
		"scan_date":             time.Now().Format(time.RFC3339),
		"total_vulnerabilities": len(vulnerabilities),
		"vulnerabilities":       vulnerabilities,
	}
}

func (p *ProxyServer) cloneRequest(orig *repository.Request) *repository.Request {
	cloned := &repository.Request{
		ID:         orig.ID,
		Method:     orig.Method,
		URL:        orig.URL,
		Body:       orig.Body,
		GetParams:  make(map[string]string),
		PostParams: make(map[string]string),
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	for k, v := range orig.GetParams {
		cloned.GetParams[k] = v
	}
	for k, v := range orig.PostParams {
		cloned.PostParams[k] = v
	}
	for k, v := range orig.Headers {
		cloned.Headers[k] = v
	}
	for k, v := range orig.Cookies {
		cloned.Cookies[k] = v
	}

	return cloned
}

func (p *ProxyServer) sendModifiedRequest(req *repository.Request) (*http.Response, error) {
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}

	q := httpReq.URL.Query()
	for k, v := range req.GetParams {
		q.Add(k, v)
	}
	httpReq.URL.RawQuery = q.Encode()

	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		if len(req.PostParams) > 0 {
			form := url.Values{}
			for k, v := range req.PostParams {
				form.Add(k, v)
			}
			httpReq.Body = io.NopCloser(strings.NewReader(form.Encode()))
			httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	for k, v := range req.Headers {
		httpReq.Header.Add(k, v)
	}

	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	client := &http.Client{}
	return client.Do(httpReq)
}

func (p *ProxyServer) isResponseVulnerable(resp *http.Response) bool {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), "root:") ||
		strings.Contains(string(body), "/bin/bash") ||
		strings.Contains(string(body), "/etc/passwd")
}
