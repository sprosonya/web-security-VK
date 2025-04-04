package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"proxy/cfg"
	"sync"
)

type ProxyServer struct {
	CA          *tls.Certificate
	CertDir     string
	CertCounter int
	mu          sync.Mutex
}

func (s *ProxyServer) Start(cfg *cfg.Config) error {
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		err := exec.Command("./bin/gen_ca.sh").Run()
		if err != nil {
			return fmt.Errorf("Failed to generate CA: %v", err)
		}
	}

	caCert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		return fmt.Errorf("Failed to load CA certificate: %v", err)
	}

	certDir := "certs"
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		os.Mkdir(certDir, 0755)
	}

	s.CA = &caCert
	s.CertDir = certDir

	server := &http.Server{
		Addr: cfg.ProxyServer.Host + ":" + cfg.ProxyServer.Port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				s.handlerHTTPS(w, r)
			} else {
				s.handlerHTTP(w, r)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Println("Starting proxy server on :8080")
	err = server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("Failed to start proxy server: %v", err)
	}
	return nil
}
