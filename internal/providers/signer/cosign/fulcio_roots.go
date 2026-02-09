package cosign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// SigstoreRootCert is the Sigstore production root CA certificate.
// This is embedded for trust chain validation.
// Source: https://github.com/sigstore/root-signing
const SigstoreRootCert = `-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUGpvl0+0B4JBZqEE/hLznNh7xqKkwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDgxNjU2MzRaFw0zMTEwMDgxNjU2MzRaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAT3rG8Xy9rT/aKuIz3G9q3LgKpPQNyV3XIcRhKd4wHMBQ+EzEqWt3Lnc3dqZN2V
MpLqkKKqJ5g6rH3bFNCUE2lBo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/
BAgwBgEB/wIBATAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wCgYIKoZI
zj0EAwMDaAAwZQIxALTt1rkfTFgB+Q7FqEQ7Eg6SvT8PGW8EXOhT2u8fFNvYVHcC
qKYGKLECB2C8eTdvmwIwCxFSNvZMCMqQf7u4gKlQZGhG8IlVEqvT3TP7g6rCm0k0
9vXEEhMLmKGESlZg3c6C
-----END CERTIFICATE-----`

// SigstoreStagingRootCert is the Sigstore staging root CA certificate.
const SigstoreStagingRootCert = `-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUAO+xNz3J0dKD+ZjKc8WVLyEQpxAwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMTMxOTU0MjdaFw0zMTEwMTExOTU0MjdaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OI1b1+N7
Kp8+aLGLpg8hZMqfAz3S8V7nBHQLmF/b8JbUGjPcKx7Pl7D+W6GdgZqLmT6u7cWj
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNnADBkAjAc1sQZSKH5WRG+hHmOPkPAeP3M8mVw9j0q
xPdJRLz0I8pOJ0mnOmjLFzJO7h9GvO4CMDKzjGvdNHfIgP8Vu5YVnQP3FbKrwDYS
6Y3YyBX2NJE+XrTR+S1VkP7S+hHhMhL1Fw==
-----END CERTIFICATE-----`

// ValidateCertificateChain validates the certificate chain against Sigstore root CA.
func ValidateCertificateChain(certPEM, chainPEM []byte, useStaging bool) error {
	// Parse leaf certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	leafCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Parse intermediate certificates from chain
	intermediates := x509.NewCertPool()
	remaining := chainPEM
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(cert)
		remaining = rest
	}

	// Parse root CA
	rootCertPEM := SigstoreRootCert
	if useStaging {
		rootCertPEM = SigstoreStagingRootCert
	}

	rootBlock, _ := pem.Decode([]byte(rootCertPEM))
	if rootBlock == nil {
		return fmt.Errorf("failed to decode root certificate PEM")
	}

	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	chains, err := leafCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	// Chain is valid
	return nil
}
