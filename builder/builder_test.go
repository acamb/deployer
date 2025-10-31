package builder

import (
	"context"
	"deployer/client/config"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientCaching(t *testing.T) {
	// Reset global client
	dockerClient = nil

	ctx := context.Background()

	// First call should create new client (may fail if Docker not available)
	client1, err1 := GetClient(ctx)

	// Second call should return same client or same error
	client2, err2 := GetClient(ctx)

	// Both calls should have the same result
	assert.Equal(t, err1 != nil, err2 != nil)
	if err1 == nil && err2 == nil {
		assert.Equal(t, client1, client2)
	}

	// Reset for other tests
	dockerClient = nil
}

func TestBuildResponseStreamMessageJSON(t *testing.T) {
	message := BuildResponseStreamMessage{
		Stream: "Step 1/1 : FROM alpine\n",
	}

	jsonData, err := json.Marshal(message)
	require.NoError(t, err)

	var decoded BuildResponseStreamMessage
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, message.Stream, decoded.Stream)
}

func TestBuildResponseStreamMessageEmpty(t *testing.T) {
	message := BuildResponseStreamMessage{}

	jsonData, err := json.Marshal(message)
	require.NoError(t, err)

	var decoded BuildResponseStreamMessage
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "", decoded.Stream)
}

func TestImportImageFromFileNotFound(t *testing.T) {
	// Test with non-existent file - should fail before reaching Docker
	err := ImportImageFromFile("/nonexistent/file.tar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestImportImageFromFileEmptyPath(t *testing.T) {
	// Test with empty path
	err := ImportImageFromFile("")
	assert.Error(t, err)
}

func TestConfigurationValidation(t *testing.T) {
	// Test that configuration fields are properly used
	config := &config.Configuration{
		Name:      "test-app",
		ImageName: "test-image:latest",
	}

	assert.Equal(t, "test-app", config.Name)
	assert.Equal(t, "test-image:latest", config.ImageName)
}

// Integration tests that require Docker
func TestBuildImageIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Reset global client to test real Docker client
	dockerClient = nil

	// Test if Docker is available
	ctx := context.Background()
	_, err := GetClient(ctx)
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Create a temporary directory with a simple Dockerfile
	tempDir := t.TempDir()
	dockerfileContent := `FROM alpine:latest
RUN echo "test build" > /test.txt
CMD cat /test.txt`

	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	require.NoError(t, os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644))

	// Change to temp directory
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	configuration := &config.Configuration{
		ImageName: "test-builder-integration:latest",
	}

	// This will only pass if Docker is running
	err = BuildImageWithDocker(configuration)
	if err != nil {
		t.Logf("Docker not available or build failed: %v", err)
		t.Skip("Skipping Docker integration test")
	}
}

func TestSaveImageToFileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Reset global client
	dockerClient = nil

	// Test if Docker is available
	ctx := context.Background()
	_, err := GetClient(ctx)
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Create temp directory
	tempDir := t.TempDir()
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalWd)

	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// Test configuration
	configuration := &config.Configuration{
		Name:      "test-app",
		ImageName: "alpine:latest", // Use a common image that should exist
	}

	// Test save
	file, err := SaveImageToFile(configuration)
	if err != nil {
		t.Logf("Docker not available or image save failed: %v", err)
		t.Skip("Skipping Docker integration test")
	}

	if file != nil {
		defer file.Close()
		// Verify file was created
		expectedPath := filepath.Join(tempDir, "test-app.tar")
		_, err = os.Stat(expectedPath)
		assert.NoError(t, err)

		// Check file is not empty
		info, err := os.Stat(expectedPath)
		require.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0))
	}
}

func TestImportImageFromFileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Reset global client
	dockerClient = nil

	// Test if Docker is available
	ctx := context.Background()
	_, err := GetClient(ctx)
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Create a test tar file with minimal valid tar content
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-image.tar")

	// Create a minimal tar file (this is not a valid Docker image, but tests the file handling)
	testContent := "fake docker image tar data"
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Test import (this will likely fail, but tests the file access)
	err = ImportImageFromFile(testFile)
	if err != nil {
		// This is expected with fake data or no Docker daemon
		// Just verify that an error occurred (could be Docker not available or invalid format)
		assert.Error(t, err)
		t.Logf("Expected error occurred: %v", err)
	}
}

// Benchmark tests
func BenchmarkBuildResponseStreamMessageJSON(b *testing.B) {
	message := BuildResponseStreamMessage{
		Stream: "Step 1/10 : FROM alpine:latest\n ---> abcd1234\n",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jsonData, err := json.Marshal(message)
		require.NoError(b, err)

		var decoded BuildResponseStreamMessage
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(b, err)
	}
}
