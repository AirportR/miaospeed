package preconfigs

import (
	"crypto/tls"
	"crypto/x509"
	"path"
	"sort"
	"strings"
)

// clientCAPool stores optional trusted client CAs for mTLS.
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

const embeddedTLSDir = "embeded/tls"

// tlsCertPriority fixes the serving order of the embedded certificates, given by
// file name without extension.
var tlsCertPriority = []string{"miaospeed_tls", "miaoko"}

func sortTLSCertNames(names []string) []string {
	rank := func(name string) int {
		for i, preferred := range tlsCertPriority {
			if name == preferred {
				return i
			}
		}
		return len(tlsCertPriority)
	}
	sort.Slice(names, func(i, j int) bool {
		if rank(names[i]) != rank(names[j]) {
			return rank(names[i]) < rank(names[j])
		}
		return names[i] < names[j]
	})
	return names
}

// loadEmbeddedTLSCerts reads every complete .crt/.key pair out of the embedded
// TLS directory, in serving order.
func loadEmbeddedTLSCerts() []tls.Certificate {
	entries, err := tlsEmbedFS.ReadDir(embeddedTLSDir)
	if err != nil {
		panic("preconfigs: cannot read the embedded TLS directory " + embeddedTLSDir + ": " + err.Error())
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".crt"))
		}
	}

	certs := make([]tls.Certificate, 0, len(names))
	for _, name := range sortTLSCertNames(names) {
		crtPEM, err := tlsEmbedFS.ReadFile(path.Join(embeddedTLSDir, name+".crt"))
		if err != nil {
			panic("preconfigs: cannot read the embedded certificate " + name + ".crt: " + err.Error())
		}
		keyPEM, err := tlsEmbedFS.ReadFile(path.Join(embeddedTLSDir, name+".key"))
		if err != nil {
			panic("preconfigs: the embedded certificate " + name + ".crt has no " + name + ".key next to it")
		}
		cert, err := tls.X509KeyPair(crtPEM, keyPEM)
		if err != nil {
			panic("preconfigs: cannot load the embedded certificate " + name + ": " + err.Error())
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		panic("preconfigs: " + embeddedTLSDir + " holds no usable TLS certificate pair")
	}
	return certs
}

// overrideServerCert, when set through -serverpublickey / -serverprivatekey,
// replaces the embedded certificates outright.
var overrideServerCert *tls.Certificate

// SetServerCertificate replaces the embedded certificates with the given PEM
// pair, instead of serving the pair next to them.
func SetServerCertificate(crtPEM, keyPEM string) error {
	cert, err := tls.X509KeyPair([]byte(crtPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	overrideServerCert = &cert
	return nil
}

func MakeSelfSignedTLSServer() *tls.Config {
	// The pair given at runtime wins outright: once -serverpublickey /
	// -serverprivatekey are set, that pair is the only certificate served.
	var certs []tls.Certificate
	if overrideServerCert != nil {
		certs = []tls.Certificate{*overrideServerCert}
	} else {
		certs = loadEmbeddedTLSCerts()
	}

	// Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: certs,
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
