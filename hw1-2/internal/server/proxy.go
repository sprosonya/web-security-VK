package server

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/exec"
	"proxy/cfg"
	"proxy/internal/repository"
	"proxy/service/db"
	"sync"
)

type ProxyServer struct {
	CA          *tls.Certificate
	CertDir     string
	CertCounter int
	mu          sync.Mutex
	repo        repository.Repository
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

	dbConn, err := db.Init(cfg)
	if err != nil {
		return err
	}
	defer dbConn.Close()
	s.repo = repository.NewRepositoryService(dbConn)

	r := mux.NewRouter()
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/requests", s.handleRequests).Methods("GET")
	apiRouter.HandleFunc("/requests/{id:[0-9]+}", s.handleSingleRequest).Methods("GET")
	apiRouter.HandleFunc("/repeat/{id:[0-9]+}", s.handleRepeatRequest).Methods("POST")
	go func() {
		addr := cfg.APIServer.Host + ":" + cfg.APIServer.Port
		if err := http.ListenAndServe(addr, r); err != nil {
			log.Fatalf("API server failed: %v", err)
		}
	}()
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
