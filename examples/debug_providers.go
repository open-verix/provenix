// Package main provides a debugging example for Provenix provider system.
//
// Usage:
//   go run examples/debug_providers.go
//
// This demonstrates:
// - Provider registration
// - SBOM generation with mock provider
// - Vulnerability scanning with mock provider
// - In-toto statement creation with mock provider
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	sbomMock "github.com/open-verix/provenix/internal/providers/sbom/mock"
	"github.com/open-verix/provenix/internal/providers/scanner"
	scannerMock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	"github.com/open-verix/provenix/internal/providers/signer"
	signerMock "github.com/open-verix/provenix/internal/providers/signer/mock"
)

func main() {
	fmt.Println("=== Provenix Provider System Debug ===")
	fmt.Println()

	// Step 1: Register providers
	fmt.Println("Step 1: Registering providers...")
	registerProviders()
	listProviders()
	fmt.Println()

	// Step 2: Generate SBOM
	fmt.Println("Step 2: Generating SBOM...")
	sbomResult, err := generateSBOM("nginx:latest")
	if err != nil {
		log.Fatalf("SBOM generation failed: %v", err)
	}
	printSBOM(sbomResult)
	fmt.Println()

	// Step 3: Scan vulnerabilities
	fmt.Println("Step 3: Scanning vulnerabilities...")
	report, err := scanVulnerabilities(sbomResult)
	if err != nil {
		log.Fatalf("Vulnerability scan failed: %v", err)
	}
	printScanReport(report)
	fmt.Println()

	// Step 4: Create signature
	fmt.Println("Step 4: Creating signature...")
	signature, err := createSignature(sbomResult, report)
	if err != nil {
		log.Fatalf("Signature creation failed: %v", err)
	}
	printSignature(signature)
	fmt.Println()

	fmt.Println("=== All steps completed successfully! ===")
}

// registerProviders registers mock providers for testing.
func registerProviders() {
	providers.RegisterSBOMProvider("mock", sbomMock.NewProvider())
	providers.RegisterScannerProvider("mock", scannerMock.NewProvider())
	providers.RegisterSignerProvider("mock", signerMock.NewProvider())
	
	fmt.Println("  ✓ Registered SBOM provider: mock")
	fmt.Println("  ✓ Registered Scanner provider: mock")
	fmt.Println("  ✓ Registered Signer provider: mock")
}

// listProviders lists all registered providers.
func listProviders() {
	fmt.Println("\nRegistered providers:")
	fmt.Printf("  SBOM providers: %v\n", providers.ListSBOMProviders())
	fmt.Printf("  Scanner providers: %v\n", providers.ListScannerProviders())
	fmt.Printf("  Signer providers: %v\n", providers.ListSignerProviders())
}

// generateSBOM generates an SBOM using the mock provider.
func generateSBOM(artifact string) (*sbom.SBOM, error) {
	provider, err := providers.GetSBOMProvider("mock")
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := sbom.DefaultOptions()
	opts.Format = sbom.FormatCycloneDXJSON

	fmt.Printf("  Artifact: %s\n", artifact)
	fmt.Printf("  Format: %s\n", opts.Format)
	fmt.Printf("  Provider: %s v%s\n", provider.Name(), provider.Version())

	result, err := provider.Generate(ctx, artifact, opts)
	if err != nil {
		return nil, fmt.Errorf("SBOM generation failed: %w", err)
	}

	return result, nil
}

// printSBOM prints SBOM details.
func printSBOM(s *sbom.SBOM) {
	fmt.Println("\n  SBOM Details:")
	fmt.Printf("    Format: %s\n", s.Format)
	fmt.Printf("    Artifact: %s\n", s.Artifact)
	fmt.Printf("    Checksum: %s\n", s.Checksum)
	fmt.Printf("    Generated: %s\n", s.GeneratedAt.Format(time.RFC3339))
	fmt.Printf("    Provider: %s v%s\n", s.ProviderName, s.ProviderVersion)
	
	// Pretty print content (first 500 chars)
	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(s.Content, &prettyJSON); err == nil {
		formatted, _ := json.MarshalIndent(prettyJSON, "    ", "  ")
		contentStr := string(formatted)
		if len(contentStr) > 500 {
			contentStr = contentStr[:500] + "..."
		}
		fmt.Printf("    Content: %s\n", contentStr)
	}
}

// scanVulnerabilities scans the SBOM for vulnerabilities.
func scanVulnerabilities(sbomResult *sbom.SBOM) (*scanner.Report, error) {
	provider, err := providers.GetScannerProvider("mock")
	if err != nil {
		return nil, fmt.Errorf("failed to get scanner provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	input := scanner.ScanInput{
		SBOM: sbomResult,
	}
	opts := scanner.DefaultOptions()

	fmt.Printf("  Provider: %s v%s\n", provider.Name(), provider.Version())
	fmt.Printf("  Input: SBOM for %s\n", sbomResult.Artifact)

	report, err := provider.Scan(ctx, input, opts)
	if err != nil {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	return report, nil
}

// printScanReport prints vulnerability scan report details.
func printScanReport(r *scanner.Report) {
	fmt.Println("\n  Scan Report Details:")
	fmt.Printf("    Artifact: %s\n", r.Artifact)
	fmt.Printf("    Checksum: %s\n", r.Checksum)
	fmt.Printf("    Scanned: %s\n", r.ScannedAt.Format(time.RFC3339))
	fmt.Printf("    Provider: %s v%s\n", r.ProviderName, r.ProviderVersion)
	
	stats := r.Stats()
	fmt.Println("\n  Vulnerability Statistics:")
	fmt.Printf("    Critical: %d\n", stats[scanner.SeverityCritical])
	fmt.Printf("    High: %d\n", stats[scanner.SeverityHigh])
	fmt.Printf("    Medium: %d\n", stats[scanner.SeverityMedium])
	fmt.Printf("    Low: %d\n", stats[scanner.SeverityLow])
	fmt.Printf("    Total: %d\n", len(r.Vulnerabilities))

	if len(r.Vulnerabilities) > 0 {
		fmt.Println("\n  Sample Vulnerabilities:")
		max := 3
		if len(r.Vulnerabilities) < max {
			max = len(r.Vulnerabilities)
		}
		for i := 0; i < max; i++ {
			v := r.Vulnerabilities[i]
			fmt.Printf("    [%s] %s - %s %s\n", v.Severity, v.ID, v.Package, v.Version)
		}
	}
}

// createSignature creates a mock signature over the evidence.
func createSignature(sbomResult *sbom.SBOM, report *scanner.Report) (*signer.Signature, error) {
	provider, err := providers.GetSignerProvider("mock")
	if err != nil {
		return nil, fmt.Errorf("failed to get signer provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create in-toto statement
	statement := &signer.Statement{
		Type: "https://in-toto.io/Statement/v0.1",
		Subject: []signer.Subject{
			{
				Name: sbomResult.Artifact,
				Digest: map[string]string{
					"sha256": sbomResult.Checksum,
				},
			},
		},
		PredicateType: "https://provenix.dev/attestation/v1",
		Predicate:     json.RawMessage(`{"sbom": "included", "scan": "included"}`),
	}

	opts := signer.DefaultOptions()
	// For mock testing, we don't validate options
	// In real usage, keyless mode would use OIDC
	fmt.Printf("  Mode: %s\n", opts.Mode)

	fmt.Printf("  Provider: %s v%s\n", provider.Name(), provider.Version())
	fmt.Printf("  Statement Type: %s\n", statement.Type)
	fmt.Printf("  Predicate Type: %s\n", statement.PredicateType)

	signature, err := provider.Sign(ctx, statement, opts)
	if err != nil {
		return nil, fmt.Errorf("signature creation failed: %w", err)
	}

	return signature, nil
}

// printSignature prints signature details.
func printSignature(sig *signer.Signature) {
	fmt.Println("\n  Signature Details:")
	fmt.Printf("    Signed: %s\n", sig.SignedAt.Format(time.RFC3339))
	fmt.Printf("    Provider: %s v%s\n", sig.SignerProvider, sig.SignerVersion)
	fmt.Printf("    Signature (first 64 chars): %s...\n", sig.Signature[:min(64, len(sig.Signature))])
	
	if sig.Certificate != "" {
		fmt.Printf("    Certificate: Present (%d chars)\n", len(sig.Certificate))
	}
	if sig.PublicKey != "" {
		fmt.Printf("    Public Key: Present (%d chars)\n", len(sig.PublicKey))
	}
	if sig.RekorEntry != "" {
		fmt.Printf("    Rekor Entry: %s\n", sig.RekorEntry)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
