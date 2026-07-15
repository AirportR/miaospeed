package preconfigs

import (
	"crypto/tls"
	"crypto/x509"
)

// clientCAPool stores optional trusted client CAs for mTLS.
// When set, clients that present a certificate must chain to one of these CAs;
// clients that present no certificate are still allowed through.
var clientCAPool *x509.CertPool

// SetClientCAPool sets the pool of trusted client CAs for optional mTLS verification.
func SetClientCAPool(pool *x509.CertPool) {
	clientCAPool = pool
}

// LoadClientCAFromPEM parses PEM-encoded certificates and sets them as the
// trusted client CA pool. Returns true on success.
func LoadClientCAFromPEM(pemData string) bool {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM([]byte(pemData)) {
		clientCAPool = pool
		return true
	}
	return false
}

func MakeSelfSignedTLSServer() *tls.Config {
	cert, _ := tls.X509KeyPair([]byte(MIAOKO_TLS_CRT), []byte(MIAOKO_TLS_KEY))

	// Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// If a client CA pool is configured, enable best-effort mTLS:
	// verify client certificates if presented, but allow connections without one.
	if clientCAPool != nil {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = clientCAPool
	}

	return tlsConfig
}

func MiaokoRootCAPrepare() *x509.CertPool {
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(MIAOKO_ROOT_CA)
	return rootCAs
}
