package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func (p *ProxyServer) getCert(hostname string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.CertCounter++

	caCert, err := x509.ParseCertificate(p.CA.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %v", err)
	}

	serial := big.NewInt(int64(p.CertCounter))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caCert,
		&priv.PublicKey,
		p.CA.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes, p.CA.Certificate[0]},
		PrivateKey:  priv,
		Leaf:        leafCert,
	}, nil
}
