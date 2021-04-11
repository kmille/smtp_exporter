package prober

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"time"
)

func getTLSVersion(state *tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unkown"
	}
}

func getCertExpiry(state *tls.ConnectionState) time.Time {
	return state.PeerCertificates[0].NotAfter
}

func getFingerprint(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}
