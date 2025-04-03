package server

import (
	"crypto/tls"
	"log"
	"net/http"
	"proxy/cfg"
)

type ProxyServer struct {
	server *http.Server
	caCert []byte
	caKey  []byte
}

func (s *ProxyServer) Start(cfg *cfg.Config) error {
	caCert, caKey, err := loadCA()
	if err != nil {
		return err
	}
	s.caCert = caCert
	s.caKey = caKey

	s.server = &http.Server{
		Addr: cfg.ProxyServer.Host + ":" + cfg.ProxyServer.Port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				s.handleHTTPS(w, r)
			} else {
				s.handleHTTP(w, r)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Println("Server is running on", "port", cfg.ProxyServer.Port)
	return s.server.ListenAndServe()
}
