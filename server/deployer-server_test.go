package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"deployer/client/version"
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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// hasUnixPermissions reports whether the filesystem honours unix mode bits.
// Windows does not: os.WriteFile(path, data, 0600) still reports 0666, so any
// check based on mode&0077 can never be satisfied there. The server itself only
// ever runs on Linux (systemd unit, deb/rpm packages), so the permission checks
// are simply not exercised on Windows developer machines.
func hasUnixPermissions() bool {
	return runtime.GOOS != "windows"
}

// DuplexMockSSHChannel with separate reader and writeBuf,
// enabling bidirectional communication for handleRequest.
// The reader can be *bytes.Buffer or an io.PipeReader for streaming.
type DuplexMockSSHChannel struct {
	reader   io.Reader
	writeBuf *bytes.Buffer
}

func (d *DuplexMockSSHChannel) Read(data []byte) (int, error) {
	return d.reader.Read(data)
}

func (d *DuplexMockSSHChannel) Write(data []byte) (int, error) {
	return d.writeBuf.Write(data)
}

func (d *DuplexMockSSHChannel) Close() error      { return nil }
func (d *DuplexMockSSHChannel) CloseWrite() error { return nil }
func (d *DuplexMockSSHChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
	return false, nil
}
func (d *DuplexMockSSHChannel) Stderr() io.ReadWriter { return &bytes.Buffer{} }

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

func setupTestEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	config = &serverConfig.ServerConfiguration{
		Port:             7676,
		ListenAddress:    "127.0.0.1",
		WorkingDirectory: tempDir,
		HostKeyPath:      filepath.Join(tempDir, "host_key"),
	}

	err := os.MkdirAll(config.WorkingDirectory, 0770)
	require.NoError(t, err)
}

// Global variables for test key cleanup
var testHostKeys []string
var testPublicKeys []ssh.PublicKey

func createTestHostKey(t *testing.T, keyPath string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key: unable to create test key - %v", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	err = os.WriteFile(keyPath, privateKeyBytes, 0600)
	if err != nil {
		t.Fatalf("Error writing key: unable to save test key to %s - %v", keyPath, err)
	}

	testHostKeys = append(testHostKeys, keyPath)
}

func generateTestSSHPublicKey(t *testing.T) (ssh.PublicKey, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating RSA key for SSH: unable to create key pair - %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Error converting SSH public key: invalid key - %v", err)
	}

	publicKeyString := string(ssh.MarshalAuthorizedKey(publicKey))
	testPublicKeys = append(testPublicKeys, publicKey)

	return publicKey, publicKeyString
}

func cleanupTestKeys(t *testing.T) {
	for _, keyPath := range testHostKeys {
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			t.Logf("Warning: unable to remove test key %s: %v", keyPath, err)
		}
	}

	testHostKeys = nil
	testPublicKeys = nil
}

func createTestAuthorizedKeys(t *testing.T, keyPath string, validKeys []string) {
	content := strings.Join(validKeys, "\n")
	err := os.WriteFile(keyPath, []byte(content), 0600)
	require.NoError(t, err)
}

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
	if !hasUnixPermissions() {
		// checkAuthorizedKey gates on checkFilePermissions, so every accept path
		// is unreachable on Windows.
		t.Skip("checkAuthorizedKey requires 0600 authorized_keys, unreachable on Windows")
	}
	setupTestEnvironment(t)

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
		{
			name: "File with invalid key line followed by valid key",
			setupFunc: func(t *testing.T) (ssh.PublicKey, string) {
				clientPublicKey, testPublicKey := generateTestSSHPublicKey(t)
				authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")
				content := []string{
					"this-is-not-a-valid-ssh-key",
					testPublicKey,
				}
				createTestAuthorizedKeys(t, authorizedKeysPath, content)
				return clientPublicKey, authorizedKeysPath
			},
			expectError: false, // valid key found after skipping the invalid one
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
	if !hasUnixPermissions() {
		t.Skip("checkFilePermissions inspects unix mode bits, which Windows does not have")
	}
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
		name             string
		request          protocol.Request
		containerName    string
		content          string
		setupFunc        func(t *testing.T, containerName string, revision string)
		expectError      bool
		errorMessage     string
		skipContentCheck bool
	}{
		{
			name: "Valid compose file",
			request: protocol.Request{
				Name: "test-app",
			},
			containerName: "test-app",
			content:       "services:\\n  web:\\n    image: nginx\n",
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError: false,
		},
		{
			name: "Valid compose file and revision",
			request: protocol.Request{
				Name:     "test-app",
				Revision: "1",
			},
			containerName: "test-app",
			content:       "services:\\n  web:\\n    image: test-app\n",
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName+"/1", 0770)
				require.NoError(t, err)
			},
			expectError: false,
		},
		{
			name: "Empty file",
			request: protocol.Request{
				Name: "empty-app",
			},
			containerName: "empty-app",
			content:       "",
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:      false,
			skipContentCheck: true,
		},
		{
			name: "Large file",
			request: protocol.Request{
				Name: "large-app",
			},
			containerName: "large-app",
			content:       strings.Repeat("# Large compose file\\n", 1000),
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:      false,
			skipContentCheck: true,
		},
		{
			name: "Missing container directory",
			request: protocol.Request{
				Name: "missing-dir",
			},
			containerName: "missing-dir",
			content:       "version: '3'",
			setupFunc:     func(t *testing.T, containerName string, revision string) {},
			expectError:   true,
			errorMessage:  "Error opening file",
		},
		{
			name: "Revision modifies image and container_name",
			request: protocol.Request{
				Name:     "rev-app",
				Revision: "42",
			},
			containerName: "rev-app",
			content: `services:
  rev-app:
    image: myimage
    container_name: mycontainer
`,
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName+"/"+revision, 0770)
				require.NoError(t, err)
			},
			expectError:      false,
			skipContentCheck: true,
		},
		{
			name: "Revision with image that already has tag",
			request: protocol.Request{
				Name:     "tagged-app",
				Revision: "99",
			},
			containerName: "tagged-app",
			content: `services:
  tagged-app:
    image: myimage:latest
`,
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName+"/"+revision, 0770)
				require.NoError(t, err)
			},
			expectError:      false,
			skipContentCheck: true,
		},
		{
			name: "Revision but service not found in compose",
			request: protocol.Request{
				Name:     "other-app",
				Revision: "5",
			},
			containerName: "other-app",
			content: `services:
  different-service:
    image: myimage
`,
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName+"/"+revision, 0770)
				require.NoError(t, err)
			},
			expectError:  true,
			errorMessage: "Compose file does not contain service other-app",
		},
		{
			name: "Invalid YAML content",
			request: protocol.Request{
				Name: "yaml-error-app",
			},
			containerName: "yaml-error-app",
			content:       "services:\n  bad: [unclosed bracket\n",
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:  true,
			errorMessage: "Error parsing compose file content",
		},
		{
			name: "Revision with missing image field in service",
			request: protocol.Request{
				Name:     "no-image-app",
				Revision: "3",
			},
			containerName: "no-image-app",
			content: `services:
  no-image-app:
    build: .
`,
			setupFunc: func(t *testing.T, containerName string, revision string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName+"/"+revision, 0770)
				require.NoError(t, err)
			},
			expectError:  true,
			errorMessage: "Compose file must specify an image for service no-image-app",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName, tc.request.Revision)

			err := saveComposeFile(tc.request, tc.content)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)

				// Verify file was created with correct content
				filePath := config.WorkingDirectory + "/" + tc.containerName + "/"
				if tc.request.Revision != "" {
					filePath += tc.request.Revision + "/"
				}
				filePath += "docker-compose.yml"
				savedContent, readErr := os.ReadFile(filePath)
				assert.NoError(t, readErr)
				if !tc.skipContentCheck {
					assert.Equal(t, tc.content, string(savedContent))
				}
				// Verify file permissions
				if hasUnixPermissions() {
					fileInfo, statErr := os.Stat(filePath)
					assert.NoError(t, statErr)
					assert.Equal(t, os.FileMode(0600), fileInfo.Mode())
				}
			}
		})
	}
}

func TestReceiveStreamedTar(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		tarData       []byte
		tarSize       int64
		containerName string
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "Valid tar data",
			tarData:       []byte("fake tar content"),
			tarSize:       int64(len("fake tar content")),
			containerName: "test-app",
			expectError:   false,
		},
		{
			name:          "Empty tar data",
			tarData:       []byte{},
			tarSize:       0,
			containerName: "empty-tar",
			expectError:   false,
		},
		{
			name:          "Large tar file",
			tarData:       bytes.Repeat([]byte("X"), 10000),
			tarSize:       10000,
			containerName: "large-tar",
			expectError:   false,
		},
		{
			name:          "Corrupted zlib data",
			tarData:       nil, // not used - we write raw bytes directly
			tarSize:       16,
			containerName: "corrupt-tar",
			expectError:   true,
			errorMessage:  "error writing tar file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var channelBuf *bytes.Buffer
			if tc.tarData == nil {
				// Valid zlib header (0x78 0x9C) followed by garbage to trigger decompression error
				channelBuf = bytes.NewBuffer([]byte{0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
			} else {
				var compressed bytes.Buffer
				writer := zlib.NewWriter(&compressed)
				_, err := writer.Write(tc.tarData)
				require.NoError(t, err)
				_ = writer.Close()
				channelBuf = bytes.NewBuffer(compressed.Bytes())
			}
			mockChannel := &MockSSHChannel{
				Buffer: channelBuf,
				closed: false,
			}

			tarFileName, err := receiveStreamedTar(mockChannel, tc.containerName, tc.tarSize)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
				assert.Equal(t, tarFileName, "")
			} else {
				assert.NoError(t, err)
				require.NotNil(t, tarFileName)

				assert.FileExists(t, tarFileName)

				if len(tc.tarData) > 0 {
					tarFile, err := os.Open(tarFileName)
					defer tarFile.Close()
					assert.NoError(t, err)
					savedContent, readErr := io.ReadAll(tarFile)
					assert.NoError(t, readErr)
					assert.Equal(t, tc.tarData, savedContent)
				}

				os.Remove(tarFileName)
			}
		})
	}
}

func TestStopContainer(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		request       protocol.Request
		containerName string
		setupFunc     func(t *testing.T, containerName string)
		expectError   bool
		errorMessage  string
	}{
		{
			name: "Valid container directory",
			request: protocol.Request{
				Name: "test-app",
			},
			containerName: "test-app",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:  true,
			errorMessage: "Error stopping container: exit status 1. Output: no configuration file provided: not found",
		},
		{
			name: "Missing container directory",
			request: protocol.Request{
				Name: "missing-app",
			},
			containerName: "missing-app",
			setupFunc:     func(t *testing.T, containerName string) {},
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName)

			err := stopContainer(tc.request)

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

func TestStopContainerOkDeleteFiles(t *testing.T) {
	setupTestEnvironment(t)
	t.Run("Stop container and delete files", func(t *testing.T) {
		containerName := "test-app"
		request := protocol.Request{
			Name:        "test-app",
			DeleteFiles: true,
		}
		err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
		require.NoError(t, err)
		err = stopContainer(request)
		assert.Error(t, err)
		//on error we don't want to delete files
		_, statErr := os.Stat(config.WorkingDirectory + "/" + containerName)
		assert.False(t, os.IsNotExist(statErr), "Container directory should be deleted")
	})
}

func TestStopContainerErrorAndDontDeleteFiles(t *testing.T) {
	setupTestEnvironment(t)
	t.Run("Stop container and delete files", func(t *testing.T) {
		containerName := "test-app"
		request := protocol.Request{
			Name:        "test-app",
			DeleteFiles: true,
		}
		err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
		require.NoError(t, err)
		TestingMode = true //simulate success on docker-compose down
		err = stopContainer(request)
		TestingMode = false
		assert.NoError(t, err)
		//on error we don't want to delete files
		_, statErr := os.Stat(config.WorkingDirectory + "/" + containerName)
		assert.True(t, os.IsNotExist(statErr), "Container directory should be deleted")
	})
}

func TestProtocolVersionMatch(t *testing.T) {
	setupTestEnvironment(t)
	t.Run("Protocol version mismatch", func(t *testing.T) {
		mockChannel := &MockSSHChannel{
			Buffer: &bytes.Buffer{},
			closed: false,
		}
		encoder := gob.NewEncoder(mockChannel)
		decoder := gob.NewDecoder(mockChannel)
		err := encoder.Encode(protocol.Request{
			Version:     "invalid-version",
			Command:     protocol.Deploy,
			Name:        "test-app",
			TarSize:     0,
			ComposeFile: []byte("version: '3'\nservices:\n  web:\n    image: nginx"),
		})
		require.NoError(t, err)

		handleRequest(mockChannel)

		response := &protocol.Response{}
		err = decoder.Decode(response)
		require.NoError(t, err)

		assert.Equal(t, protocol.Ko, response.Status)
		assert.Contains(t, response.Message, "Protocol version mismatch")
	})
}

func TestProtocolRequestStructure(t *testing.T) {
	testCases := []struct {
		name    string
		request protocol.Request
	}{
		{
			name: "Valid deploy request",
			request: protocol.Request{
				Version:     version.Version,
				Command:     protocol.Deploy,
				Name:        "test-app",
				TarSize:     1024,
				ComposeFile: []byte("version: '3'\nservices:\n  web:\n    image: nginx"),
			},
		},
		{
			name: "Request with only compose file",
			request: protocol.Request{
				Version:     version.Version,
				Command:     protocol.Start,
				Name:        "compose-only",
				TarSize:     0,
				ComposeFile: []byte("version: '3'"),
			},
		},
		{
			name: "Empty request",
			request: protocol.Request{
				Version:     version.Version,
				Command:     protocol.Stop,
				Name:        "empty-app",
				TarSize:     0,
				ComposeFile: nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			encoder := gob.NewEncoder(&buffer)
			decoder := gob.NewDecoder(&buffer)

			err := encoder.Encode(&tc.request)
			assert.NoError(t, err)

			var decoded protocol.Request
			err = decoder.Decode(&decoded)
			assert.NoError(t, err)

			assert.Equal(t, tc.request.Command, decoded.Command)
			assert.Equal(t, tc.request.Name, decoded.Name)
			assert.Equal(t, tc.request.TarSize, decoded.TarSize)
			assert.Equal(t, tc.request.ComposeFile, decoded.ComposeFile)
		})
	}
}

func TestStartContainer(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name          string
		request       protocol.Request
		containerName string
		composeFile   string
		setupFunc     func(t *testing.T, containerName string)
		expectError   bool
		errorMessage  string
	}{
		{
			name: "Valid container with compose content",
			request: protocol.Request{
				Name: "not-exists",
				ComposeFile: []byte(`
services:
  test:
    image: not-exists
`),
			},
			containerName: "not-exists",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:  true, // if this fails with the specified error it's ok
			errorMessage: "Error pull access denied for not-exists",
		},
		{
			name: "Valid container with compose content and invalid revision",
			request: protocol.Request{
				Name: "not-exists",
				ComposeFile: []byte(`
services:
  test:
    image: not-exists
`),
				Revision: "42",
			},
			containerName: "not-exists",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:  true, // if this fails with the specified error it's ok
			errorMessage: "Error opening file for writing",
		},
		{
			name: "Empty compose file",
			request: protocol.Request{
				Name:        "empty-compose",
				ComposeFile: []byte(""),
			},
			containerName: "empty-compose",
			setupFunc: func(t *testing.T, containerName string) {
				err := os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770)
				require.NoError(t, err)
			},
			expectError:  true,
			errorMessage: "no configuration file provided: not found",
		},
		{
			name: "missing-dir",
			request: protocol.Request{
				Name:        "missing-dir",
				ComposeFile: []byte("version: '3'"),
			},
			containerName: "missing-dir",
			setupFunc:     func(t *testing.T, containerName string) {},
			expectError:   true,
			errorMessage:  "Error opening file for writing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFunc(t, tc.containerName)

			err := startContainer(tc.request)

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

func TestTimeoutHandler(t *testing.T) {
	t.Run("Write updates lastActivity", func(t *testing.T) {
		th := &TimeoutHandler{}
		before := th.lastActivity.Load()

		n, err := th.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Greater(t, th.lastActivity.Load(), before)
	})

	t.Run("Write with empty slice", func(t *testing.T) {
		th := &TimeoutHandler{}
		n, err := th.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("StartMonitoring fires after inactivity timeout", func(t *testing.T) {
		th := &TimeoutHandler{}
		// Start monitoring with a very short timeout (200ms)
		ch := th.StartMonitoring(200 * time.Millisecond)

		// Write once to set lastActivity, then stop writing
		_, _ = th.Write([]byte("ping"))

		// Wait for timeout signal (should arrive within ~300ms after last write)
		select {
		case _, ok := <-ch:
			// channel closed or value received means timeout fired
			_ = ok
		case <-time.After(2 * time.Second):
			t.Fatal("timeout monitor did not fire within expected time")
		}
	})

	t.Run("StartMonitoring resets on continuous activity", func(t *testing.T) {
		th := &TimeoutHandler{}
		ch := th.StartMonitoring(300 * time.Millisecond)

		// Keep writing for 400ms to stay active, then stop
		done := make(chan struct{})
		go func() {
			defer close(done)
			deadline := time.Now().Add(400 * time.Millisecond)
			for time.Now().Before(deadline) {
				_, _ = th.Write([]byte("activity"))
				time.Sleep(50 * time.Millisecond)
			}
		}()
		<-done

		// After activity stops, timeout should fire eventually
		select {
		case <-ch:
			// good
		case <-time.After(2 * time.Second):
			t.Fatal("timeout monitor did not fire after activity stopped")
		}
	})
}

func TestGetWorkingDirectory(t *testing.T) {
	setupTestEnvironment(t)

	testCases := []struct {
		name     string
		request  protocol.Request
		expected string
	}{
		{
			name: "Without revision",
			request: protocol.Request{
				Name: "myapp",
			},
			expected: config.WorkingDirectory + "/myapp",
		},
		{
			name: "With revision",
			request: protocol.Request{
				Name:     "myapp",
				Revision: "42",
			},
			expected: config.WorkingDirectory + "/myapp/42",
		},
		{
			name: "Empty revision treated as no revision",
			request: protocol.Request{
				Name:     "myapp",
				Revision: "",
			},
			expected: config.WorkingDirectory + "/myapp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getWorkingDirectory(tc.request)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParsePortsOutput(t *testing.T) {
	testCases := []struct {
		name         string
		output       string
		expectError  bool
		errorMessage string
		expectPorts  []protocol.Port
	}{
		{
			name:        "Single port",
			output:      "80/tcp -> 0.0.0.0:8080\n",
			expectError: false,
			expectPorts: []protocol.Port{
				{LocalPort: "80", BindPort: "8080", Protocol: "tcp", Address: "0.0.0.0"},
			},
		},
		{
			name:        "Multiple ports",
			output:      "80/tcp -> 0.0.0.0:8080\n443/tcp -> 0.0.0.0:8443\n",
			expectError: false,
			expectPorts: []protocol.Port{
				{LocalPort: "80", BindPort: "8080", Protocol: "tcp", Address: "0.0.0.0"},
				{LocalPort: "443", BindPort: "8443", Protocol: "tcp", Address: "0.0.0.0"},
			},
		},
		{
			name:        "Multiple ports, ipv6",
			output:      "80/tcp -> 0.0.0.0:8080\n443/tcp -> [::]:8080\n",
			expectError: false,
			expectPorts: []protocol.Port{
				{LocalPort: "80", BindPort: "8080", Protocol: "tcp", Address: "0.0.0.0"},
				{LocalPort: "443", BindPort: "8080", Protocol: "tcp", Address: "::"},
			},
		},
		{
			name:        "Empty output",
			output:      "",
			expectError: false,
			expectPorts: nil,
		},
		{
			name:        "Output with blank lines",
			output:      "\n80/tcp -> 0.0.0.0:8080\n\n",
			expectError: false,
			expectPorts: []protocol.Port{
				{LocalPort: "80", BindPort: "8080", Protocol: "tcp", Address: "0.0.0.0"},
			},
		},
		{
			name:         "Malformed line - missing protocol",
			output:       "80 -> 0.0.0.0:8080\n",
			expectError:  true,
			errorMessage: "Error parsing ports binding for",
		},
		{
			name:         "Malformed line - missing host port",
			output:       "80/tcp -> 0.0.0.0\n",
			expectError:  true,
			errorMessage: "Error parsing ports binding for",
		},
		{
			name:        "UDP port",
			output:      "53/udp -> 0.0.0.0:5353\n",
			expectError: false,
			expectPorts: []protocol.Port{
				{LocalPort: "53", BindPort: "5353", Protocol: "udp", Address: "0.0.0.0"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := parsePortsOutput(tc.output)
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectPorts, ports)
			}
		})
	}
}

func TestParseRevisionsList(t *testing.T) {
	testCases := []struct {
		name            string
		output          string
		expectRevisions []string
	}{
		{
			name:            "Single container",
			output:          "abc123 myapp-1\n",
			expectRevisions: []string{"myapp-1"},
		},
		{
			name:            "Multiple containers",
			output:          "abc123 myapp-1\ndef456 myapp-2\n",
			expectRevisions: []string{"myapp-1", "myapp-2"},
		},
		{
			name:            "Empty output",
			output:          "",
			expectRevisions: nil,
		},
		{
			name:            "Output with blank lines",
			output:          "\nabc123 myapp-1\n\n",
			expectRevisions: []string{"myapp-1"},
		},
		{
			name:            "Line without space - skipped",
			output:          "abc123\ndef456 myapp-2\n",
			expectRevisions: []string{"myapp-2"},
		},
		{
			name:            "Container name with spaces",
			output:          "abc123 myapp revision 1\n",
			expectRevisions: []string{"myapp revision 1"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			revisions := parseRevisionsList(tc.output)
			assert.Equal(t, tc.expectRevisions, revisions)
		})
	}
}

func TestHandleRequest_Commands(t *testing.T) {
	setupTestEnvironment(t)

	// serverVersion is "dev" - same as client/version.Version in this test build
	const serverVersion = "dev"

	// helper: encode a request into a fresh channel and call handleRequest,
	// then decode and return the first response.
	runRequest := func(t *testing.T, req protocol.Request) protocol.Response {
		t.Helper()
		ch := &MockSSHChannel{Buffer: &bytes.Buffer{}, closed: false}
		enc := gob.NewEncoder(ch)
		dec := gob.NewDecoder(ch)
		require.NoError(t, enc.Encode(req))
		handleRequest(ch)
		var resp protocol.Response
		require.NoError(t, dec.Decode(&resp))
		return resp
	}

	t.Run("Stop_missing_directory_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Stop,
			Name:    "nonexistent-stop-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Error stopping container")
	})

	t.Run("Stop_TestingMode_returns_Ok", func(t *testing.T) {
		containerName := "stop-ok-app"
		require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))
		TestingMode = true
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Stop,
			Name:    containerName,
		})
		TestingMode = false
		assert.Equal(t, protocol.Ok, resp.Status)
		assert.Contains(t, resp.Message, "stopped successfully")
	})

	t.Run("Start_missing_directory_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version:     serverVersion,
			Command:     protocol.Start,
			Name:        "nonexistent-start-app",
			ComposeFile: []byte(""),
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Error starting container")
	})

	t.Run("Deploy_no_tar_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version:     serverVersion,
			Command:     protocol.Deploy,
			Name:        "deploy-app",
			TarSize:     0,
			ComposeFile: []byte("services:\n  web:\n    image: nginx"),
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "No tar file supplied")
	})

	t.Run("Push_no_tar_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version:     serverVersion,
			Command:     protocol.Push,
			Name:        "push-app",
			TarSize:     0,
			ComposeFile: []byte("services:\n  web:\n    image: nginx"),
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "No tar file supplied")
	})

	t.Run("Restart_missing_directory_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Restart,
			Name:    "nonexistent-restart-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Error stopping container")
	})

	t.Run("Revisions_docker_unavailable_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Revisions,
			Name:    "nonexistent-rev-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Error retrieving revisions")
	})

	t.Run("Ports_docker_unavailable_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Ports,
			Name:    "nonexistent-ports-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Error retrieving ports")
	})

	t.Run("Logs_missing_directory_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Logs,
			Name:    "nonexistent-logs-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		// cmd.Start() fails because working directory doesn't exist
		assert.Contains(t, resp.Message, "Error running logs command")
	})

	t.Run("Unknown_command_returns_Ko", func(t *testing.T) {
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Command(99),
			Name:    "unknown-app",
		})
		assert.Equal(t, protocol.Ko, resp.Status)
		assert.Contains(t, resp.Message, "Unknown command")
	})

	t.Run("Decode_error_returns_silently", func(t *testing.T) {
		// Send invalid gob bytes — handleRequest should log and return without sending a response
		ch := &MockSSHChannel{Buffer: bytes.NewBuffer([]byte("this is not gob")), closed: false}
		handleRequest(ch)
		// Buffer should be empty (no response written) or contain nothing decodable as Response
		var resp protocol.Response
		err := gob.NewDecoder(ch).Decode(&resp)
		assert.Error(t, err, "expected no valid response after decode error")
	})

	t.Run("Deploy_TarSize_positive_zlib_error_returns_Ko", func(t *testing.T) {
		// Use DuplexMockSSHChannel: server reads request from readBuf, writes responses to writeBuf.
		// readBuf is empty after request → zlib.NewReader on empty stream returns ErrHeader.
		readBuf := &bytes.Buffer{}
		writeBuf := &bytes.Buffer{}
		require.NoError(t, gob.NewEncoder(readBuf).Encode(protocol.Request{
			Version:     serverVersion,
			Command:     protocol.Deploy,
			Name:        "deploy-tar-app",
			TarSize:     1024,
			ComposeFile: []byte("services:\n  web:\n    image: nginx"),
		}))
		ch := &DuplexMockSSHChannel{reader: readBuf, writeBuf: writeBuf}
		handleRequest(ch)

		dec := gob.NewDecoder(writeBuf)
		var okResp protocol.Response
		require.NoError(t, dec.Decode(&okResp), "expected ok response")
		assert.Equal(t, protocol.Ok, okResp.Status)
		assert.Equal(t, "ok", okResp.Message)

		var errResp protocol.Response
		require.NoError(t, dec.Decode(&errResp), "expected error response")
		assert.Equal(t, protocol.Ko, errResp.Status)
		assert.Contains(t, errResp.Message, "Error receiving tar file")
	})

	t.Run("Push_TarSize_positive_zlib_error_returns_Ko", func(t *testing.T) {
		readBuf := &bytes.Buffer{}
		writeBuf := &bytes.Buffer{}
		require.NoError(t, gob.NewEncoder(readBuf).Encode(protocol.Request{
			Version:     serverVersion,
			Command:     protocol.Push,
			Name:        "push-tar-app",
			TarSize:     512,
			ComposeFile: []byte("services:\n  web:\n    image: nginx"),
		}))
		ch := &DuplexMockSSHChannel{reader: readBuf, writeBuf: writeBuf}
		handleRequest(ch)

		dec := gob.NewDecoder(writeBuf)
		var okResp protocol.Response
		require.NoError(t, dec.Decode(&okResp))
		assert.Equal(t, protocol.Ok, okResp.Status)

		var errResp protocol.Response
		require.NoError(t, dec.Decode(&errResp))
		assert.Equal(t, protocol.Ko, errResp.Status)
		assert.Contains(t, errResp.Message, "Error receiving tar file")
	})

	t.Run("Revisions_empty_result_returns_Ok_with_json", func(t *testing.T) {
		containerName := "revisions-ok-app"
		require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Revisions,
			Name:    containerName,
		})
		// docker ps works (empty result for non-running containers) → Ok JSON response
		assert.Equal(t, protocol.Ok, resp.Status)
		assert.Contains(t, resp.Message, "revisions")
	})

	t.Run("Logs_existing_directory_returns_Fine_log", func(t *testing.T) {
		containerName := "logs-ok-app"
		require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))
		// cmd.Start() succeeds; docker compose exits immediately (no compose file) → "End of logs stream"
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Logs,
			Name:    containerName,
		})
		assert.Equal(t, protocol.Ok, resp.Status)
		assert.Contains(t, resp.Message, "End of logs stream")
	})

	t.Run("Deploy_valid_tar_ImportImageFails_returns_Ko", func(t *testing.T) {
		// Use io.Pipe so gob cannot read ahead past the request boundary.
		// The goroutine feeds: request bytes, then a valid empty zlib stream.
		// receiveStreamedTar succeeds (empty tar file), then ImportImageFromFile fails.
		pr, pw := io.Pipe()
		writeBuf := &bytes.Buffer{}
		ch := &DuplexMockSSHChannel{reader: pr, writeBuf: writeBuf}

		go func() {
			defer pw.Close()
			_ = gob.NewEncoder(pw).Encode(protocol.Request{
				Version:     serverVersion,
				Command:     protocol.Deploy,
				Name:        "deploy-pipe-app",
				TarSize:     1,
				ComposeFile: []byte("services:\n  web:\n    image: nginx"),
			})
			// Write a valid empty zlib stream so receiveStreamedTar succeeds
			var zlibData bytes.Buffer
			zlibWriter := zlib.NewWriter(&zlibData)
			_ = zlibWriter.Close()
			_, _ = pw.Write(zlibData.Bytes())
		}()

		handleRequest(ch)

		dec := gob.NewDecoder(writeBuf)
		var okResp protocol.Response
		require.NoError(t, dec.Decode(&okResp), "expected ok handshake response")
		assert.Equal(t, protocol.Ok, okResp.Status)
		assert.Equal(t, "ok", okResp.Message)

		var errResp protocol.Response
		require.NoError(t, dec.Decode(&errResp), "expected error response after import failure")
		assert.Equal(t, protocol.Ko, errResp.Status)
	})

	t.Run("Push_TestingMode_success_returns_Ok", func(t *testing.T) {
		pr, pw := io.Pipe()
		writeBuf := &bytes.Buffer{}
		ch := &DuplexMockSSHChannel{reader: pr, writeBuf: writeBuf}

		go func() {
			defer pw.Close()
			_ = gob.NewEncoder(pw).Encode(protocol.Request{
				Version: serverVersion,
				Command: protocol.Push,
				Name:    "push-testmode-app",
				TarSize: 1,
				ComposeFile: []byte(`services:
  push-testmode-app:
    image: myimage
`),
			})
			var zlibData bytes.Buffer
			zlibWriter := zlib.NewWriter(&zlibData)
			_ = zlibWriter.Close()
			_, _ = pw.Write(zlibData.Bytes())
		}()

		TestingMode = true
		handleRequest(ch)
		TestingMode = false

		dec := gob.NewDecoder(writeBuf)
		var okHandshake protocol.Response
		require.NoError(t, dec.Decode(&okHandshake))
		assert.Equal(t, protocol.Ok, okHandshake.Status)

		var successResp protocol.Response
		require.NoError(t, dec.Decode(&successResp))
		assert.Equal(t, protocol.Ok, successResp.Status)
		assert.Contains(t, successResp.Message, "imported successfully")
	})

	t.Run("Start_TestingMode_success_returns_Ok", func(t *testing.T) {
		containerName := "start-testmode-app"
		require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))
		TestingMode = true
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Start,
			Name:    containerName,
			ComposeFile: []byte(`services:
  start-testmode-app:
    image: myimage
`),
		})
		TestingMode = false
		assert.Equal(t, protocol.Ok, resp.Status)
		assert.Contains(t, resp.Message, "started successfully")
	})

	t.Run("Restart_TestingMode_success_returns_Ok", func(t *testing.T) {
		containerName := "restart-testmode-app"
		require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))
		TestingMode = true
		resp := runRequest(t, protocol.Request{
			Version: serverVersion,
			Command: protocol.Restart,
			Name:    containerName,
		})
		TestingMode = false
		assert.Equal(t, protocol.Ok, resp.Status)
		assert.Contains(t, resp.Message, "started successfully")
	})

	t.Run("Deploy_TestingMode_full_success_returns_Ok", func(t *testing.T) {
		pr, pw := io.Pipe()
		writeBuf := &bytes.Buffer{}
		ch := &DuplexMockSSHChannel{reader: pr, writeBuf: writeBuf}

		go func() {
			defer pw.Close()
			_ = gob.NewEncoder(pw).Encode(protocol.Request{
				Version: serverVersion,
				Command: protocol.Deploy,
				Name:    "deploy-full-app",
				TarSize: 1,
				Prune:   true,
				ComposeFile: []byte(`services:
  deploy-full-app:
    image: myimage
`),
			})
			var zlibData bytes.Buffer
			zlibWriter := zlib.NewWriter(&zlibData)
			_ = zlibWriter.Close()
			_, _ = pw.Write(zlibData.Bytes())
		}()

		TestingMode = true
		handleRequest(ch)
		TestingMode = false

		dec := gob.NewDecoder(writeBuf)
		var okHandshake protocol.Response
		require.NoError(t, dec.Decode(&okHandshake))
		assert.Equal(t, protocol.Ok, okHandshake.Status)

		var successResp protocol.Response
		require.NoError(t, dec.Decode(&successResp))
		assert.Equal(t, protocol.Ok, successResp.Status)
		assert.Contains(t, successResp.Message, "started successfully")
	})

	t.Run("Deploy_TestingMode_invalid_compose_saveComposeFile_fails", func(t *testing.T) {
		// saveTarAndImport succeeds (TestingMode), but saveComposeFile fails (invalid YAML).
		pr, pw := io.Pipe()
		writeBuf := &bytes.Buffer{}
		ch := &DuplexMockSSHChannel{reader: pr, writeBuf: writeBuf}

		go func() {
			defer pw.Close()
			_ = gob.NewEncoder(pw).Encode(protocol.Request{
				Version:     serverVersion,
				Command:     protocol.Deploy,
				Name:        "deploy-compose-fail-app",
				TarSize:     1,
				ComposeFile: []byte("services:\n  bad: [unclosed bracket\n"),
			})
			var zlibData bytes.Buffer
			zlibWriter := zlib.NewWriter(&zlibData)
			_ = zlibWriter.Close()
			_, _ = pw.Write(zlibData.Bytes())
		}()

		TestingMode = true
		handleRequest(ch)
		TestingMode = false

		dec := gob.NewDecoder(writeBuf)
		var okHandshake protocol.Response
		require.NoError(t, dec.Decode(&okHandshake))
		assert.Equal(t, protocol.Ok, okHandshake.Status)

		var errResp protocol.Response
		require.NoError(t, dec.Decode(&errResp))
		assert.Equal(t, protocol.Ko, errResp.Status)
		assert.Contains(t, errResp.Message, "Error saving compose file")
	})
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

func TestWriteEphemeralPrivateKey(t *testing.T) {
	keyData := []byte("super-secret-key-content")
	// Copy because writeEphemeralPrivateKey zeros the buffer on cleanup.
	keyCopy := make([]byte, len(keyData))
	copy(keyCopy, keyData)

	path, cleanup, err := writeEphemeralPrivateKey(keyCopy)
	require.NoError(t, err)
	require.NotEmpty(t, path)
	require.NotNil(t, cleanup)

	// File exists with 0600 permissions and correct content.
	if hasUnixPermissions() {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, keyData, got)

	cleanup()

	// File removed and in-memory buffer zeroed.
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
	for _, b := range keyCopy {
		assert.Equal(t, byte(0), b)
	}
}

func TestBuildStartCommand_NoEkvs(t *testing.T) {
	setupTestEnvironment(t)
	name, args, cleanup, err := buildStartCommand(protocol.Request{Name: "x"})
	require.NoError(t, err)
	assert.Nil(t, cleanup)
	assert.Equal(t, "docker", name)
	assert.Equal(t, []string{"compose", "up", "-d"}, args)
}

func TestBuildStartCommand_WithEkvs(t *testing.T) {
	setupTestEnvironment(t)
	config.EkvsBin = "/usr/local/bin/ekvs"
	defer func() { config.EkvsBin = "" }()

	req := protocol.Request{
		Name:           "x",
		EkvsEnable:     true,
		EkvsServer:     "https://ekvs.example.com",
		EkvsProject:    "myproj",
		EkvsPrivateKey: []byte("key-bytes"),
	}
	name, args, cleanup, err := buildStartCommand(req)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	defer cleanup()

	assert.Equal(t, "/usr/local/bin/ekvs", name)
	// Expected pattern: --server URL --identity <tmp> exec proj -- docker compose up -d
	require.GreaterOrEqual(t, len(args), 9)
	assert.Equal(t, "--server", args[0])
	assert.Equal(t, "https://ekvs.example.com", args[1])
	assert.Equal(t, "--identity", args[2])
	assert.FileExists(t, args[3])
	assert.Equal(t, "exec", args[4])
	assert.Equal(t, "myproj", args[5])
	assert.Equal(t, "--", args[6])
	assert.Equal(t, "docker", args[7])
	assert.Equal(t, "compose", args[8])
	assert.Equal(t, "up", args[9])
	assert.Equal(t, "-d", args[10])
}

func TestBuildStartCommand_EkvsDefaultsToPath(t *testing.T) {
	setupTestEnvironment(t)
	// EkvsBin not set → fallback to "ekvs" from PATH.
	name, args, cleanup, err := buildStartCommand(protocol.Request{
		Name:           "x",
		EkvsEnable:     true,
		EkvsServer:     "https://ekvs.example.com",
		EkvsProject:    "myproj",
		EkvsPrivateKey: []byte("key-bytes"),
	})
	require.NoError(t, err)
	defer cleanup()
	assert.Equal(t, "ekvs", name)
	_ = args
}

func TestBuildStartCommand_EkvsMissingKey(t *testing.T) {
	setupTestEnvironment(t)
	_, _, _, err := buildStartCommand(protocol.Request{
		Name:        "x",
		EkvsEnable:  true,
		EkvsServer:  "https://ekvs.example.com",
		EkvsProject: "myproj",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no private key")
}

func TestBuildStartCommand_EkvsMissingServer(t *testing.T) {
	setupTestEnvironment(t)
	_, _, _, err := buildStartCommand(protocol.Request{
		Name:           "x",
		EkvsEnable:     true,
		EkvsProject:    "myproj",
		EkvsPrivateKey: []byte("k"),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no server")
}

func TestBuildStartCommand_EkvsMissingProject(t *testing.T) {
	setupTestEnvironment(t)
	_, _, _, err := buildStartCommand(protocol.Request{
		Name:           "x",
		EkvsEnable:     true,
		EkvsServer:     "https://ekvs.example.com",
		EkvsPrivateKey: []byte("k"),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no project")
}

func TestStartContainer_EkvsCommandNotFound(t *testing.T) {
	setupTestEnvironment(t)
	containerName := "ekvs-app"
	require.NoError(t, os.MkdirAll(config.WorkingDirectory+"/"+containerName, 0770))

	// Point EkvsBin to a nonexistent binary so the exec fails and the error
	// is propagated up to the caller (and consequently to the client).
	config.EkvsBin = filepath.Join(t.TempDir(), "nonexistent-ekvs")
	defer func() { config.EkvsBin = "" }()

	err := startContainer(protocol.Request{
		Name:           containerName,
		EkvsEnable:     true,
		EkvsServer:     "https://ekvs.example.com",
		EkvsProject:    "myproj",
		EkvsPrivateKey: []byte("key-bytes"),
		ComposeFile:    []byte("services:\n  ekvs-app:\n    image: nginx\n"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Error starting container")
}
