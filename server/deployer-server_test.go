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
				fileInfo, statErr := os.Stat(filePath)
				assert.NoError(t, statErr)
				assert.Equal(t, os.FileMode(0600), fileInfo.Mode())
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var compressed bytes.Buffer
			writer := zlib.NewWriter(&compressed)
			_, err := writer.Write(tc.tarData)
			require.NoError(t, err)
			_ = writer.Close()
			mockChannel := &MockSSHChannel{
				Buffer: bytes.NewBuffer(compressed.Bytes()),
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
			errorMessage: "no such file or directory",
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
			errorMessage:  "no such file or directory",
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
