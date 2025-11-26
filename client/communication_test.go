package client

import (
	"bytes"
	"deployer/protocol"
	"encoding/gob"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// MockChannel implements ssh.Channel for testing
type MockChannel struct {
	*bytes.Buffer
	closed bool
}

func (m *MockChannel) Read(data []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.Buffer.Read(data)
}

func (m *MockChannel) Write(data []byte) (int, error) {
	if m.closed {
		return 0, errors.New("channel closed")
	}
	return m.Buffer.Write(data)
}

func (m *MockChannel) Close() error {
	m.closed = true
	return nil
}

func (m *MockChannel) CloseWrite() error {
	return nil
}

func (m *MockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *MockChannel) Stderr() io.ReadWriter {
	return m.Buffer
}

// MockSSHConn implements ssh.Conn for testing
type MockSSHConn struct {
	mockChannel *MockChannel
}

func (m *MockSSHConn) OpenChannel(channelType string, extraData []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if channelType == "session" {
		return m.mockChannel, make(<-chan *ssh.Request), nil
	}
	return nil, nil, errors.New("unsupported channel type")
}

func (m *MockSSHConn) Close() error {
	return nil
}

func (m *MockSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return true, nil, nil
}

func (m *MockSSHConn) Wait() error {
	return nil
}

func (m *MockSSHConn) User() string {
	return "test"
}

func (m *MockSSHConn) SessionID() []byte {
	return []byte("test-session")
}

func (m *MockSSHConn) ClientVersion() []byte {
	return []byte("SSH-2.0-test")
}

func (m *MockSSHConn) ServerVersion() []byte {
	return []byte("SSH-2.0-test-server")
}

func (m *MockSSHConn) RemoteAddr() string {
	return "127.0.0.1:22"
}

func (m *MockSSHConn) LocalAddr() string {
	return "127.0.0.1:12345"
}

func setupMockConnection(t *testing.T) *MockChannel {
	mockChannel := &MockChannel{
		Buffer: &bytes.Buffer{},
		closed: false,
	}

	// Set global variables to use mock
	// Note: This is a simplified mock - in a real implementation
	// we would need proper dependency injection
	dataChannel = mockChannel
	encoder = gob.NewEncoder(mockChannel)
	decoder = gob.NewDecoder(mockChannel)

	return mockChannel
}

func TestStartContainer(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Pre-encode a success response in the mock channel
	response := protocol.Response{
		Status:  protocol.Ok,
		Message: "Container started successfully",
	}
	err := gob.NewEncoder(mockChannel).Encode(&response)
	require.NoError(t, err)

	// Reset the read position
	responseData := mockChannel.Bytes()
	mockChannel.Reset()
	mockChannel.Write(responseData)

	// Call the function
	err = StartContainer("test-container", -1)
	assert.NoError(t, err)
}

func TestStopContainer(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Pre-encode a success response
	response := protocol.Response{
		Status:  protocol.Ok,
		Message: "Container stopped successfully",
	}
	responseBuffer := &bytes.Buffer{}
	err := gob.NewEncoder(responseBuffer).Encode(&response)
	require.NoError(t, err)

	// Setup mock to return this response
	mockChannel.Write(responseBuffer.Bytes())

	err = StopContainer("test-container", -1)
	assert.NoError(t, err)
}

func TestRestartContainer(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Pre-encode a success response
	response := protocol.Response{
		Status:  protocol.Ok,
		Message: "Container restarted successfully",
	}
	responseBuffer := &bytes.Buffer{}
	err := gob.NewEncoder(responseBuffer).Encode(&response)
	require.NoError(t, err)

	mockChannel.Write(responseBuffer.Bytes())

	err = RestartContainer("test-container", -1)
	assert.NoError(t, err)
}

func TestContainerError(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Pre-encode an error response
	response := protocol.Response{
		Status:  protocol.Ko,
		Message: "Container not found",
	}
	responseBuffer := &bytes.Buffer{}
	err := gob.NewEncoder(responseBuffer).Encode(&response)
	require.NoError(t, err)

	mockChannel.Write(responseBuffer.Bytes())

	err = StartContainer("nonexistent-container", -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Container not found")
}

func TestDeployImage(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Create temporary files for testing
	tempDir := t.TempDir()

	// Create a fake tar file
	tarFile := filepath.Join(tempDir, "test.tar")
	tarData := []byte("fake tar data")
	require.NoError(t, os.WriteFile(tarFile, tarData, 0644))

	// Create a fake compose file
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	composeData := []byte("version: '3'\nservices:\n  test:\n    image: test")
	require.NoError(t, os.WriteFile(composeFile, composeData, 0644))

	composeFileHandle, err := os.Open(composeFile)
	require.NoError(t, err)
	defer composeFileHandle.Close()

	// Pre-encode a success response
	response := protocol.Response{
		Status:  protocol.Ok,
		Message: "Deployment successful",
	}
	responseBuffer := &bytes.Buffer{}
	err = gob.NewEncoder(responseBuffer).Encode(&response)
	require.NoError(t, err)

	mockChannel.Write(responseBuffer.Bytes())

	err = DeployImage("test-app", tarFile, composeFileHandle, -1)
	assert.NoError(t, err)
}

func TestLogsStreaming(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Pre-encode multiple log responses
	logResponses := []protocol.Response{
		{Status: protocol.Ok, Message: "Log line 1"},
		{Status: protocol.Ok, Message: "Log line 2"},
		{Status: protocol.Ok, Message: "Log line 3"},
		{Status: protocol.Ko, Message: "End of logs"}, // This should end the stream
	}

	responseBuffer := &bytes.Buffer{}
	encoder := gob.NewEncoder(responseBuffer)
	for _, resp := range logResponses {
		err := encoder.Encode(&resp)
		require.NoError(t, err)
	}

	mockChannel.Write(responseBuffer.Bytes())

	logChan, err := Logs("test-container", -1)
	require.NoError(t, err)
	assert.NotNil(t, logChan)

	// Collect logs
	var logs []string
	for log := range logChan {
		logs = append(logs, log)
	}

	// Should receive 3 log lines (the Ko response ends the stream)
	assert.Len(t, logs, 3)
	assert.Equal(t, "Log line 1", logs[0])
	assert.Equal(t, "Log line 2", logs[1])
	assert.Equal(t, "Log line 3", logs[2])
}

func TestHandleRequestEncoding(t *testing.T) {
	mockChannel := setupMockConnection(t)

	// Create temporary files
	tempDir := t.TempDir()
	tarFile := filepath.Join(tempDir, "test.tar")
	composeFile := filepath.Join(tempDir, "compose.yml")

	tarData := []byte("test tar content")
	composeData := []byte("version: '3'")

	require.NoError(t, os.WriteFile(tarFile, tarData, 0644))
	require.NoError(t, os.WriteFile(composeFile, composeData, 0644))

	composeFileHandle, err := os.Open(composeFile)
	require.NoError(t, err)
	defer composeFileHandle.Close()

	// Pre-encode success response
	response := protocol.Response{
		Status:  protocol.Ok,
		Message: "Success",
	}
	responseBuffer := &bytes.Buffer{}
	err = gob.NewEncoder(responseBuffer).Encode(&response)
	require.NoError(t, err)
	mockChannel.Write(responseBuffer.Bytes())

	// Call handleRequest directly
	err = handleRequest("test-container", protocol.Deploy, tarFile, composeFileHandle, -1)
	assert.NoError(t, err)
}

func TestConnectionFailure(t *testing.T) {
	// Test when connections are nil
	originalChannel := dataChannel
	originalEncoder := encoder
	originalDecoder := decoder

	defer func() {
		// Restore original values
		dataChannel = originalChannel
		encoder = originalEncoder
		decoder = originalDecoder
	}()

	// Set connections to nil to simulate failure
	dataChannel = nil
	encoder = nil
	decoder = nil

	// This should panic or fail gracefully depending on implementation
	assert.Panics(t, func() {
		StartContainer("test", -1)
	})
}

// Benchmark tests
func BenchmarkStartContainer(b *testing.B) {
	mockChannel := &MockChannel{
		Buffer: &bytes.Buffer{},
		closed: false,
	}

	// Set global variables to use mock
	dataChannel = mockChannel
	encoder = gob.NewEncoder(mockChannel)
	decoder = gob.NewDecoder(mockChannel)

	// Pre-encode responses for all iterations
	responseBuffer := &bytes.Buffer{}
	responseEncoder := gob.NewEncoder(responseBuffer)

	for i := 0; i < b.N; i++ {
		response := protocol.Response{
			Status:  protocol.Ok,
			Message: "Container started",
		}
		err := responseEncoder.Encode(&response)
		require.NoError(b, err)
	}

	mockChannel.Write(responseBuffer.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := StartContainer("benchmark-container", -1)
		require.NoError(b, err)
	}
}
