package protocol

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandString(t *testing.T) {
	tests := []struct {
		command  Command
		expected string
	}{
		{Deploy, "Deploy"},
		{Stop, "Stop"},
		{Start, "Start"},
		{Restart, "Restart"},
		{Logs, "Logs"},
		{Command(999), "Unknown Command"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.command.String())
		})
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{Ok, "Ok"},
		{Ko, "Ko"},
		{Status(999), "Unknown Status"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestRequestString(t *testing.T) {
	req := Request{
		Command: Deploy,
		Name:    "test-container",
	}

	expected := "Command: Deploy"
	assert.Equal(t, expected, req.String())
}

func TestResponseString(t *testing.T) {
	resp := Response{
		Status:  Ok,
		Message: "Success",
	}

	expected := "Status: Ok, Message: Success"
	assert.Equal(t, expected, resp.String())
}

func TestRequestGobEncoding(t *testing.T) {
	original := Request{
		Command:     Deploy,
		Name:        "test-container",
		TarImage:    []byte("fake tar data"),
		ComposeFile: []byte("version: '3'\nservices:\n  test:\n    image: nginx"),
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(&original)
	require.NoError(t, err)

	// Decode
	var decoded Request
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Command, decoded.Command)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.TarImage, decoded.TarImage)
	assert.Equal(t, original.ComposeFile, decoded.ComposeFile)
}

func TestResponseGobEncoding(t *testing.T) {
	original := Response{
		Status:  Ko,
		Message: "Container not found",
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(&original)
	require.NoError(t, err)

	// Decode
	var decoded Response
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Status, decoded.Status)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestLargeDataGobEncoding(t *testing.T) {
	// Test with large binary data
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := Request{
		Command:     Deploy,
		Name:        "large-container",
		TarImage:    largeData,
		ComposeFile: []byte("version: '3'\nservices:\n  test:\n    image: nginx"),
	}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(&original)
	require.NoError(t, err)

	// Decode
	var decoded Request
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Command, decoded.Command)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.TarImage, decoded.TarImage)
	assert.Equal(t, original.ComposeFile, decoded.ComposeFile)
}

func TestEmptyRequestGobEncoding(t *testing.T) {
	original := Request{}

	// Encode
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(&original)
	require.NoError(t, err)

	// Decode
	var decoded Request
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Command, decoded.Command)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.TarImage, decoded.TarImage)
	assert.Equal(t, original.ComposeFile, decoded.ComposeFile)
}

func TestMultipleRequestsGobEncoding(t *testing.T) {
	requests := []Request{
		{Command: Deploy, Name: "container1", TarImage: []byte("data1")},
		{Command: Start, Name: "container2"},
		{Command: Stop, Name: "container3"},
		{Command: Restart, Name: "container4"},
		{Command: Logs, Name: "container5"},
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	// Encode all requests
	for _, req := range requests {
		err := encoder.Encode(&req)
		require.NoError(t, err)
	}

	// Decode all requests
	decoder := gob.NewDecoder(&buf)
	var decoded []Request
	for i := 0; i < len(requests); i++ {
		var req Request
		err := decoder.Decode(&req)
		require.NoError(t, err)
		decoded = append(decoded, req)
	}

	// Verify
	assert.Equal(t, len(requests), len(decoded))
	for i, original := range requests {
		assert.Equal(t, original.Command, decoded[i].Command)
		assert.Equal(t, original.Name, decoded[i].Name)
		assert.Equal(t, original.TarImage, decoded[i].TarImage)
		assert.Equal(t, original.ComposeFile, decoded[i].ComposeFile)
	}
}

func TestRequestResponseSequence(t *testing.T) {
	// Simulate a client-server communication sequence
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	decoder := gob.NewDecoder(&buf)

	// Client sends request
	request := Request{
		Command:     Deploy,
		Name:        "test-app",
		TarImage:    []byte("docker image data"),
		ComposeFile: []byte("version: '3'\nservices:\n  app:\n    image: test-app"),
	}

	err := encoder.Encode(&request)
	require.NoError(t, err)

	// Server receives request
	var receivedRequest Request
	err = decoder.Decode(&receivedRequest)
	require.NoError(t, err)
	assert.Equal(t, request, receivedRequest)

	// Server sends response
	response := Response{
		Status:  Ok,
		Message: "Deployment successful",
	}

	err = encoder.Encode(&response)
	require.NoError(t, err)

	// Client receives response
	var receivedResponse Response
	err = decoder.Decode(&receivedResponse)
	require.NoError(t, err)
	assert.Equal(t, response, receivedResponse)
}

// Benchmark tests
func BenchmarkRequestGobEncoding(b *testing.B) {
	request := Request{
		Command:     Deploy,
		Name:        "benchmark-container",
		TarImage:    make([]byte, 1024), // 1KB
		ComposeFile: []byte("version: '3'\nservices:\n  test:\n    image: nginx"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		encoder := gob.NewEncoder(&buf)
		err := encoder.Encode(&request)
		require.NoError(b, err)
	}
}

func BenchmarkResponseGobEncoding(b *testing.B) {
	response := Response{
		Status:  Ok,
		Message: "Operation completed successfully",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		encoder := gob.NewEncoder(&buf)
		err := encoder.Encode(&response)
		require.NoError(b, err)
	}
}

func BenchmarkLargeRequestGobEncoding(b *testing.B) {
	// Test with larger data (1MB)
	largeData := make([]byte, 1024*1024)
	request := Request{
		Command:     Deploy,
		Name:        "large-container",
		TarImage:    largeData,
		ComposeFile: []byte("version: '3'\nservices:\n  test:\n    image: nginx"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		encoder := gob.NewEncoder(&buf)
		err := encoder.Encode(&request)
		require.NoError(b, err)
	}
}
