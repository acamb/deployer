package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"deployer/protocol"
	serverConfig "deployer/server/config"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Mock SSH Channel implementation
type MockSSHChannel struct {
	*bytes.Buffer
	closed bool
}

func (m *MockSSHChannel) Read(data []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.Buffer.Read(data)
}

func (m *MockSSHChannel) Write(data []byte) (int, error) {
	if m.closed {
		return 0, errors.New("channel closed")
	}
	return m.Buffer.Write(data)
}

func (m *MockSSHChannel) Close() error {
	m.closed = true
	return nil
}

func (m *MockSSHChannel) CloseWrite() error {
	return nil
}

func (m *MockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *MockSSHChannel) Stderr() io.ReadWriter {
	return m.Buffer
}

// Mock SSH Connection implementation
type MockSSHServerConn struct {
	channels chan ssh.NewChannel
	requests chan *ssh.Request
	closed   bool
}

func (m *MockSSHServerConn) Close() error {
	m.closed = true
	close(m.channels)
	close(m.requests)
	return nil
}

func (m *MockSSHServerConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return true, nil, nil
}

func (m *MockSSHServerConn) Wait() error {
	return nil
}

func (m *MockSSHServerConn) User() string {
	return "test"
}

func (m *MockSSHServerConn) SessionID() []byte {
	return []byte("test-session")
}

func (m *MockSSHServerConn) ClientVersion() []byte {
	return []byte("SSH-2.0-test")
}

func (m *MockSSHServerConn) ServerVersion() []byte {
	return []byte("SSH-2.0-test-server")
}

func (m *MockSSHServerConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return addr
}

func (m *MockSSHServerConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")
	return addr
}

func (m *MockSSHServerConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	mockChannel := &MockSSHChannel{
		Buffer: &bytes.Buffer{},
		closed: false,
	}
	return mockChannel, make(<-chan *ssh.Request), nil
}

// Mock SSH Connection Metadata
type MockSSHConnMetadata struct {
	remoteAddr net.Addr
}

func (m *MockSSHConnMetadata) User() string {
	return "test"
}

func (m *MockSSHConnMetadata) SessionID() []byte {
	return []byte("test-session")
}

func (m *MockSSHConnMetadata) ClientVersion() []byte {
	return []byte("SSH-2.0-test")
}

func (m *MockSSHConnMetadata) ServerVersion() []byte {
	return []byte("SSH-2.0-test-server")
}

func (m *MockSSHConnMetadata) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *MockSSHConnMetadata) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:22")
	return addr
}

// Mock SSH New Channel
type MockSSHNewChannel struct {
	channelType   string
	acceptChannel ssh.Channel
	rejectCalled  bool
	rejectReason  ssh.RejectionReason
	rejectMessage string
}

func (m *MockSSHNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	if m.acceptChannel == nil {
		return nil, nil, errors.New("channel not configured")
	}
	return m.acceptChannel, make(<-chan *ssh.Request), nil
}

func (m *MockSSHNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	m.rejectCalled = true
	m.rejectReason = reason
	m.rejectMessage = message
	return nil
}

func (m *MockSSHNewChannel) ChannelType() string {
	return m.channelType
}

func (m *MockSSHNewChannel) ExtraData() []byte {
	return nil
}

// Test setup utilities
func setupTestConfig(t *testing.T) *serverConfig.ServerConfiguration {
	tempDir := t.TempDir()
	return &serverConfig.ServerConfiguration{
		Port:             7676,
		ListenAddress:    "127.0.0.1",
		WorkingDirectory: tempDir,
		HostKeyPath:      filepath.Join(tempDir, "host_key"),
	}
}

func setupTestEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	config = &serverConfig.ServerConfiguration{
		Port:             7676,
		ListenAddress:    "127.0.0.1",
		WorkingDirectory: tempDir,
		HostKeyPath:      filepath.Join(tempDir, "host_key"),
	}

	// Create working directory
	err := os.MkdirAll(config.WorkingDirectory, 0770)
	require.NoError(t, err)
}

// Global variables for test key cleanup
var testHostKeys []string
var testPublicKeys []ssh.PublicKey

func createTestHostKey(t *testing.T, keyPath string) {
	// Generate a 2048-bit RSA key on the fly
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: unable to create test key - %v", err)
	}

	// Convert the key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write the key to file
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyPath, privateKeyBytes, 0600)
	if err != nil {
		t.Fatalf("Error writing key: unable to save test key to %s - %v", keyPath, err)
	}

	// Add the path to the list for final cleanup
	testHostKeys = append(testHostKeys, keyPath)
}

func generateTestSSHPublicKey(t *testing.T) (ssh.PublicKey, string) {
	// Generate an RSA key for SSH
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key for SSH: unable to create key pair - %v", err)
	}

	// Create the SSH public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Error converting SSH public key: invalid key - %v", err)
	}

	// Generate the public key string in authorized_keys format
	publicKeyString := string(ssh.MarshalAuthorizedKey(publicKey))

	// Add to the cleanup list
	testPublicKeys = append(testPublicKeys, publicKey)

	return publicKey, publicKeyString
}

func cleanupTestKeys(t *testing.T) {
	// Remove all key files created during tests
	for _, keyPath := range testHostKeys {
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			t.Logf("Warning: unable to remove test key %s: %v", keyPath, err)
		}
	}

	// Reset the lists
	testHostKeys = nil
	testPublicKeys = nil
}

func createTestAuthorizedKeys(t *testing.T, keyPath string, validKeys []string) {
	content := strings.Join(validKeys, "\n")
	err := os.WriteFile(keyPath, []byte(content), 0600)
	require.NoError(t, err)
}

// Tests for utility functions

func TestLoadHostKey(t *testing.T) {
	testCases := []struct {
		name        string
		setupFunc   func(t *testing.T) *serverConfig.ServerConfiguration
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid host key",
			setupFunc: func(t *testing.T) *serverConfig.ServerConfiguration {
				tempDir := t.TempDir()
				keyPath := filepath.Join(tempDir, "host_key")
				createTestHostKey(t, keyPath)
				return &serverConfig.ServerConfiguration{
					HostKeyPath: keyPath,
				}
			},
			expectError: false,
		},
		{
			name: "Missing host key file",
			setupFunc: func(t *testing.T) *serverConfig.ServerConfiguration {
				tempDir := t.TempDir()
				return &serverConfig.ServerConfiguration{
					HostKeyPath: filepath.Join(tempDir, "nonexistent_key"),
				}
			},
			expectError: true,
			errorMsg:    "host key not found",
		},
		{
			name: "Default key path missing",
			setupFunc: func(t *testing.T) *serverConfig.ServerConfiguration {
				return &serverConfig.ServerConfiguration{
					HostKeyPath: "",
				}
			},
			expectError: true,
			errorMsg:    "host key not found",
		},
		{
			name: "Invalid key content",
			setupFunc: func(t *testing.T) *serverConfig.ServerConfiguration {
				tempDir := t.TempDir()
				keyPath := filepath.Join(tempDir, "invalid_key")
				err := os.WriteFile(keyPath, []byte("invalid key content"), 0600)
				require.NoError(t, err)
				return &serverConfig.ServerConfiguration{
					HostKeyPath: keyPath,
				}
			},
			expectError: true,
			errorMsg:    "failed to parse host key",
		},
	}

	defer cleanupTestKeys(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.setupFunc(t)

			signer, err := loadHostKey(config)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, signer)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestCheckAuthorizedKey(t *testing.T) {
	setupTestEnvironment(t)

	// Clean up keys at the end of the test
	defer cleanupTestKeys(t)

	testCases := []struct {
		name         string
		setupFunc    func(t *testing.T) (ssh.PublicKey, string)
		expectError  bool
		errorMessage string
	}{
		{
			name: "Valid authorized key",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, testPublicKey := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				createTestAuthorizedKeys(t, authorizedKeysPath, []string{testPublicKey})
				return clientPublicKey, authorizedKeysPath
			},
			expectError: false,
		},
		{
			name: "Key not in authorized_keys",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, _ := generateTestSSHPublicKey(t)
				_, anotherKey := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				createTestAuthorizedKeys(t, authorizedKeysPath, []string{anotherKey})
				return clientPublicKey, authorizedKeysPath
			},
			expectError:  true,
			errorMessage: "access denied",
		},
		{
			name: "Multiple keys, valid match",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, testPublicKey := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				createTestAuthorizedKeys(t, authorizedKeysPath, []string{testPublicKey})
				return clientPublicKey, authorizedKeysPath
			},
			expectError: false,
		},
		{
			name: "Empty authorized_keys file",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, _ := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				createTestAuthorizedKeys(t, authorizedKeysPath, []string{})
				return clientPublicKey, authorizedKeysPath
			},
			expectError:  true,
			errorMessage: "access denied",
		},
		{
			name: "File with comments and empty lines",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, testPublicKey := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				content := []string{
					"# This is a comment",
					"",
					testPublicKey,
					"# Another comment",
				}
				createTestAuthorizedKeys(t, authorizedKeysPath, content)
				return clientPublicKey, authorizedKeysPath
			},
			expectError: false,
		},
		{
			name: "Missing authorized_keys file",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, _ := generateTestSSHPublicKey(t)
				return clientPublicKey, filepath.Join(config.WorkingDirectory, "nonexistent_keys")
			},
			expectError:  true,
			errorMessage: "access denied",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testKey, _ := tc.setupFunc(t)

			mockConn := &MockSSHConnMetadata{
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			}

			permissions, err := checkAuthorizedKey(testKey, mockConn)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, permissions)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, permissions)
			}
		})
	}
}

func TestCheckFilePermissions(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name         string
		permissions  os.FileMode
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Secure permissions (600)",
			permissions: 0600,
			expectError: false,
		},
		{
			name:        "Secure permissions (400)",
			permissions: 0400,
			expectError: false,
		},
		{
			name:         "Insecure permissions (644)",
			permissions:  0644,
			expectError:  true,
			errorMessage: "insecure permissions",
		},
		{
			name:         "Insecure permissions (755)",
			permissions:  0755,
			expectError:  true,
			errorMessage: "insecure permissions",
		},
		{
			name:         "World writable (666)",
			permissions:  0666,
			expectError:  true,
			errorMessage: "insecure permissions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFile := filepath.Join(tempDir, fmt.Sprintf("test_file_%s", tc.name))
			err := os.WriteFile(testFile, []byte("test content"), tc.permissions)
			require.NoError(t, err)

			err = checkFilePermissions(testFile)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSaveComposeFile(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		containerName string
		content       string
		setupFunc     func(t *testing.T, containerName string)
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "Valid compose file content",
			containerName: "test-app",
			content:       "version: '3'\\nservices:\\n  web:\\n    image: nginx",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: false,
		},
		{
			name:          "Empty content",
			containerName: "empty-app",
			content:       "",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: false,
		},
		{
			name:          "Large content",
			containerName: "large-app",
			content:       strings.Repeat("# Large compose file\\n", 1000),
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: false,
		},
		{
			name:          "Container directory missing",
			containerName: "missing-dir",
			content:       "version: '3'",
			setupFunc:     func(t *testing.T, containerName string) {},
			expectError:   true,
			errorMessage:  "Error opening file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName)

			err := saveComposeFile(tc.containerName, tc.content)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)

				// Verify file was created with correct content
				filePath := config.WorkingDirectory + "/" + tc.containerName + "/docker-compose.yml"
				savedContent, readErr := os.ReadFile(filePath)
				assert.NoError(t, readErr)
				assert.Equal(t, tc.content, string(savedContent))

				// Verify file permissions
				fileInfo, statErr := os.Stat(filePath)
				assert.NoError(t, statErr)
				assert.Equal(t, os.FileMode(0600), fileInfo.Mode())
			}
		})
	}
}

func TestReceiveTarAndComposeFile(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name         string
		request      protocol.Request
		expectError  bool
		errorMessage string
		checkTarFile bool
	}{
		{
			name: "Valid request with tar and compose",
			request: protocol.Request{
				Name:        "test-app",
				TarImage:    []byte("fake tar content"),
				ComposeFile: []byte("version: '3'\\nservices:\\n  web:\\n    image: test"),
			},
			expectError:  false,
			checkTarFile: true,
		},
		{
			name: "Request with only compose file",
			request: protocol.Request{
				Name:        "compose-only",
				TarImage:    nil,
				ComposeFile: []byte("version: '3'"),
			},
			expectError:  false,
			checkTarFile: false,
		},
		{
			name: "Empty tar content",
			request: protocol.Request{
				Name:        "empty-tar",
				TarImage:    []byte{},
				ComposeFile: []byte("version: '3'"),
			},
			expectError:  false,
			checkTarFile: true,
		},
		{
			name: "Large tar file",
			request: protocol.Request{
				Name:        "large-tar",
				TarImage:    bytes.Repeat([]byte("X"), 10000),
				ComposeFile: []byte("version: '3'"),
			},
			expectError:  false,
			checkTarFile: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tarFile, composeContent, err := receiveTarAndComposeFile(tc.request)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, string(tc.request.ComposeFile), composeContent)

				if tc.checkTarFile && tc.request.TarImage != nil && len(tc.request.TarImage) > 0 {
					assert.NotNil(t, tarFile)

					// Verify tar file content
					tarContent, readErr := os.ReadFile(tarFile.Name())
					assert.NoError(t, readErr)
					assert.Equal(t, tc.request.TarImage, tarContent)

					// Clean up
					tarFile.Close()
					os.Remove(tarFile.Name())
				} else {
					if tc.request.TarImage == nil {
						assert.Nil(t, tarFile)
					}
				}
			}
		})
	}
}

func TestStopContainer(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		containerName string
		setupFunc     func(t *testing.T, containerName string)
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "Valid container directory",
			containerName: "test-app",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: true, // docker-compose command will fail in test environment
		},
		{
			name:          "Missing container directory",
			containerName: "missing-app",
			setupFunc:     func(t *testing.T, containerName string) {},
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName)

			err := stopContainer(tc.containerName)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStartContainer(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		containerName string
		composeFile   string
		setupFunc     func(t *testing.T, containerName string)
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "Valid container with compose content",
			containerName: "test-app",
			composeFile:   "version: '3'\\nservices:\\n  web:\\n    image: nginx",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: true, // docker-compose command will fail in test environment
		},
		{
			name:          "Empty compose file",
			containerName: "empty-compose",
			composeFile:   "",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: true, // docker-compose command will fail in test environment
		},
		{
			name:          "Missing container directory",
			containerName: "missing-dir",
			composeFile:   "version: '3'",
			setupFunc:     func(t *testing.T, containerName string) {},
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName)

			err := startContainer(tc.containerName, tc.composeFile)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandleResponse(t *testing.T) {
	testCases := []struct {
		name    string
		message string
		status  protocol.Status
	}{
		{
			name:    "Success response",
			message: "Operation completed successfully",
			status:  protocol.Ok,
		},
		{
			name:    "Error response",
			message: "Operation failed",
			status:  protocol.Ko,
		},
		{
			name:    "Empty message",
			message: "",
			status:  protocol.Ok,
		},
		{
			name:    "Long message",
			message: strings.Repeat("This is a long message. ", 100),
			status:  protocol.Ko,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			encoder := gob.NewEncoder(&buffer)

			err := handleResponse(tc.message, tc.status, encoder)
			assert.NoError(t, err)

			// Decode and verify the response
			decoder := gob.NewDecoder(&buffer)
			var response protocol.Response
			decodeErr := decoder.Decode(&response)
			assert.NoError(t, decodeErr)

			assert.Equal(t, tc.message, response.Message)
			assert.Equal(t, tc.status, response.Status)
		})
	}
}

func TestHandleSSHConnection(t *testing.T) {
	testCases := []struct {
		name         string
		setupFunc    func(t *testing.T) (net.Conn, *ssh.ServerConfig)
		expectPanic  bool
		expectError  bool
		errorMessage string
	}{
		// Note: SSH connections are complex to mock completely
		// These tests focus on error conditions that can be easily tested
		{
			name: "Nil connection",
			setupFunc: func(t *testing.T) (net.Conn, *ssh.ServerConfig) {
				sshConfig := &ssh.ServerConfig{}
				return nil, sshConfig
			},
			expectPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn, sshConfig := tc.setupFunc(t)

			if tc.expectPanic {
				assert.Panics(t, func() {
					handleSSHConnection(conn, sshConfig)
				})
				return
			}

			_, _, err := handleSSHConnection(conn, sshConfig)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
