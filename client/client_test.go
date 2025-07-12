package client

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"deployer/client/config"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions for generating SSH keys dynamically

func generateEd25519Key(t *testing.T, path string) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(t, os.WriteFile(path, privateKeyPEM, 0600))
}

func generateECDSAKey(t *testing.T, path string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(t, os.WriteFile(path, privateKeyPEM, 0600))
}

func generateRSAKey(t *testing.T, path string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(t, os.WriteFile(path, privateKeyPEM, 0600))
}

func generateDSAKey(t *testing.T, path string) {
	// DSA is deprecated, so we'll use RSA as fallback for testing
	// but save it with a different name for discovery testing
	generateRSAKey(t, path)
}

func TestLoadPrivateKeySimple(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()

	// Generate a simple RSA key
	keyPath := filepath.Join(tempDir, "test_key")
	generateRSAKey(t, keyPath)

	// Test with explicit key path
	config := config.Configuration{
		PrivateKey: keyPath,
	}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ssh-rsa", signer.PublicKey().Type())
}

func TestLoadPrivateKeyAutoDiscovery(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Generate a simple RSA key
	keyPath := filepath.Join(sshDir, "id_rsa")
	generateRSAKey(t, keyPath)

	// Set HOME environment variable
	t.Setenv("HOME", tempDir)

	// Test with auto discovery
	config := config.Configuration{}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ssh-rsa", signer.PublicKey().Type())
}

func TestLoadPrivateKeyPriority(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Create RSA key first (lower priority)
	rsaPath := filepath.Join(sshDir, "id_rsa")
	generateRSAKey(t, rsaPath)

	// Set HOME environment variable
	t.Setenv("HOME", tempDir)

	// Test that it finds RSA key when only RSA is available
	config := config.Configuration{}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ssh-rsa", signer.PublicKey().Type())
}

func TestLoadPrivateKeyEd25519Priority(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Create RSA key first (lower priority)
	rsaPath := filepath.Join(sshDir, "id_rsa")
	generateRSAKey(t, rsaPath)

	// Create ECDSA key (medium priority)
	ecdsaPath := filepath.Join(sshDir, "id_ecdsa")
	generateECDSAKey(t, ecdsaPath)

	// Create Ed25519 key (highest priority)
	ed25519Path := filepath.Join(sshDir, "id_ed25519")
	generateEd25519Key(t, ed25519Path)

	// Set HOME environment variable
	t.Setenv("HOME", tempDir)

	// Test that it picks Ed25519 key (highest priority)
	config := config.Configuration{}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ssh-ed25519", signer.PublicKey().Type())
}

func TestLoadPrivateKeyECDSAOverRSA(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Create RSA key first (lower priority)
	rsaPath := filepath.Join(sshDir, "id_rsa")
	generateRSAKey(t, rsaPath)

	// Create ECDSA key (higher priority than RSA)
	ecdsaPath := filepath.Join(sshDir, "id_ecdsa")
	generateECDSAKey(t, ecdsaPath)

	// Set HOME environment variable
	t.Setenv("HOME", tempDir)

	// Test that it picks ECDSA key over RSA
	config := config.Configuration{}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ecdsa-sha2-nistp256", signer.PublicKey().Type())
}

func TestLoadPrivateKeyNoKeysFound(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))

	// Set HOME environment variable
	t.Setenv("HOME", tempDir)

	// Test with no keys
	config := config.Configuration{}

	signer, err := loadPrivateKey(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "no SSH private key found")
}

func TestLoadPrivateKeyInvalidKey(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()

	// Create invalid key file
	keyPath := filepath.Join(tempDir, "invalid_key")
	require.NoError(t, os.WriteFile(keyPath, []byte("invalid content"), 0600))

	// Test with invalid key
	config := config.Configuration{
		PrivateKey: keyPath,
	}

	signer, err := loadPrivateKey(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "failed to parse private key")
}

func TestLoadPrivateKeyEd25519(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()

	// Generate Ed25519 key
	keyPath := filepath.Join(tempDir, "test_ed25519")
	generateEd25519Key(t, keyPath)

	// Test with explicit key path
	config := config.Configuration{
		PrivateKey: keyPath,
	}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ssh-ed25519", signer.PublicKey().Type())
}

func TestLoadPrivateKeyECDSA(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()

	// Generate ECDSA key
	keyPath := filepath.Join(tempDir, "test_ecdsa")
	generateECDSAKey(t, keyPath)

	// Test with explicit key path
	config := config.Configuration{
		PrivateKey: keyPath,
	}

	signer, err := loadPrivateKey(config)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "ecdsa-sha2-nistp256", signer.PublicKey().Type())
}

// Benchmark tests for key loading with dynamic generation
func BenchmarkLoadPrivateKeyRSA(b *testing.B) {
	tempDir := b.TempDir()
	keyPath := filepath.Join(tempDir, "test_rsa")

	// Generate RSA key for benchmark
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(b, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(b, os.WriteFile(keyPath, privateKeyPEM, 0600))

	config := config.Configuration{
		PrivateKey: keyPath,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer, err := loadPrivateKey(config)
		require.NoError(b, err)
		require.NotNil(b, signer)
	}
}

func BenchmarkLoadPrivateKeyEd25519(b *testing.B) {
	tempDir := b.TempDir()
	keyPath := filepath.Join(tempDir, "test_ed25519")

	// Generate Ed25519 key for benchmark
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(b, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(b, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(b, os.WriteFile(keyPath, privateKeyPEM, 0600))

	config := config.Configuration{
		PrivateKey: keyPath,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer, err := loadPrivateKey(config)
		require.NoError(b, err)
		require.NotNil(b, signer)
	}
}

func BenchmarkLoadPrivateKeyECDSA(b *testing.B) {
	tempDir := b.TempDir()
	keyPath := filepath.Join(tempDir, "test_ecdsa")

	// Generate ECDSA key for benchmark
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(b, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	require.NoError(b, os.WriteFile(keyPath, privateKeyPEM, 0600))

	config := config.Configuration{
		PrivateKey: keyPath,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer, err := loadPrivateKey(config)
		require.NoError(b, err)
		require.NotNil(b, signer)
	}
}
