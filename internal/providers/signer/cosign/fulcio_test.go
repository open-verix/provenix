package cosign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestFulcioClient_New(t *testing.T) {
	tests := []struct {
		name           string
		fulcioURL      string
		rekorURL       string
		expectedFulcio string
		expectedRekor  string
	}{
		{
			name:           "default URLs",
			fulcioURL:      "",
			rekorURL:       "",
			expectedFulcio: "https://fulcio.sigstore.dev",
			expectedRekor:  "https://rekor.sigstore.dev",
		},
		{
			name:           "custom URLs",
			fulcioURL:      "https://fulcio.example.com",
			rekorURL:       "https://rekor.example.com",
			expectedFulcio: "https://fulcio.example.com",
			expectedRekor:  "https://rekor.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewFulcioClient(tt.fulcioURL, tt.rekorURL)
			if client.fulcioURL != tt.expectedFulcio {
				t.Errorf("fulcioURL = %v, want %v", client.fulcioURL, tt.expectedFulcio)
			}
			if client.rekorURL != tt.expectedRekor {
				t.Errorf("rekorURL = %v, want %v", client.rekorURL, tt.expectedRekor)
			}
		})
	}
}

func TestValidateCertificate(t *testing.T) {
	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := privateKey.Public()

	// Create test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-user@example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Self-sign for testing
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	client := NewFulcioClient("", "")

	tests := []struct {
		name      string
		certPEM   []byte
		pubKey    interface{}
		wantError bool
	}{
		{
			name:      "valid certificate",
			certPEM:   certPEM,
			pubKey:    publicKey,
			wantError: false,
		},
		{
			name:      "invalid PEM",
			certPEM:   []byte("not a certificate"),
			pubKey:    publicKey,
			wantError: true,
		},
		{
			name:      "mismatched public key",
			certPEM:   certPEM,
			pubKey:    func() interface{} {
				wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return wrongKey.Public()
			}(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateCertificate(tt.certPEM, tt.pubKey)
			if (err != nil) != tt.wantError {
				t.Errorf("validateCertificate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateCertificate_Expiry(t *testing.T) {
	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := privateKey.Public()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid certificate",
			notBefore: time.Now().Add(-1 * time.Hour),
			notAfter:  time.Now().Add(1 * time.Hour),
			wantError: false,
		},
		{
			name:      "not yet valid",
			notBefore: time.Now().Add(1 * time.Hour),
			notAfter:  time.Now().Add(2 * time.Hour),
			wantError: true,
			errorMsg:  "not yet valid",
		},
		{
			name:      "expired",
			notBefore: time.Now().Add(-2 * time.Hour),
			notAfter:  time.Now().Add(-1 * time.Hour),
			wantError: true,
			errorMsg:  "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "test",
				},
				NotBefore:             tt.notBefore,
				NotAfter:              tt.notAfter,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
				BasicConstraintsValid: true,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}

			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certDER,
			})

			client := NewFulcioClient("", "")
			err = client.validateCertificate(certPEM, publicKey)

			if (err != nil) != tt.wantError {
				t.Errorf("validateCertificate() error = %v, wantError %v", err, tt.wantError)
			}

			if tt.wantError && err != nil && tt.errorMsg != "" {
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("error message = %v, want to contain %v", err.Error(), tt.errorMsg)
				}
			}
		})
	}
}

func TestSignWithECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	if err != nil {
		t.Fatalf("Failed to generate digest: %v", err)
	}

	signature, err := signWithECDSA(privateKey, digest)
	if err != nil {
		t.Errorf("signWithECDSA() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("signWithECDSA() returned empty signature")
	}
}

func TestExtractPublicKeyFromCertificate(t *testing.T) {
	// Generate key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := privateKey.Public()

	// Create certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	extractedPEM, err := extractPublicKeyFromCertificate(certPEM)
	if err != nil {
		t.Errorf("extractPublicKeyFromCertificate() error = %v", err)
	}

	// Verify extracted key matches original
	expectedPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal original public key: %v", err)
	}

	if string(extractedPEM) != string(expectedPEM) {
		t.Error("Extracted public key does not match original")
	}
}

func TestExtractPublicKeyFromCertificate_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		certPEM []byte
	}{
		{
			name:    "invalid PEM",
			certPEM: []byte("not a certificate"),
		},
		{
			name: "invalid certificate data",
			certPEM: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("invalid"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractPublicKeyFromCertificate(tt.certPEM)
			if err == nil {
				t.Error("extractPublicKeyFromCertificate() expected error, got nil")
			}
		})
	}
}
