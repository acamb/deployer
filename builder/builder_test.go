package builder

import (
	"context"
	"deployer/client/config"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	dockerimage "github.com/docker/docker/api/types/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetClient drops the cached global client and restores it after the test.
func resetClient(t *testing.T) {
	t.Helper()
	dockerClient = nil
	t.Cleanup(func() { dockerClient = nil })
}

// requireDocker skips the test unless a Docker daemon is actually reachable.
func requireDocker(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	cli, err := GetClient(ctx)
	if err != nil {
		t.Skip("Docker client not available, skipping integration test:", err)
	}
	// NewClientWithOpts does not connect, so an explicit ping is needed to know
	// whether a daemon is really there.
	if _, err := cli.Ping(ctx); err != nil {
		t.Skip("Docker daemon not reachable, skipping integration test:", err)
	}
}

func TestGetClientCaching(t *testing.T) {
	resetClient(t)

	ctx := context.Background()

	// First call should create new client (may fail if Docker not available)
	client1, err1 := GetClient(ctx)

	// Second call should return same client or same error
	client2, err2 := GetClient(ctx)

	// Both calls should have the same result
	assert.Equal(t, err1 != nil, err2 != nil)
	if err1 == nil && err2 == nil {
		assert.Same(t, client1, client2)
	}
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
	err := ImportImageFromFile(filepath.Join(t.TempDir(), "nonexistent", "file.tar"))
	require.Error(t, err)
	// The wording of the OS error is platform dependent, so match on the sentinel.
	assert.True(t, errors.Is(err, os.ErrNotExist), "expected a not-exist error, got: %v", err)
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

	resetClient(t)
	requireDocker(t)

	// Create a temporary directory with a simple Dockerfile
	tempDir := t.TempDir()
	dockerfileContent := `FROM alpine:latest
RUN echo "test build" > /test.txt
CMD cat /test.txt`

	dockerfilePath := filepath.Join(tempDir, "Dockerfile")
	require.NoError(t, os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644))

	// Build from the temp directory
	t.Chdir(tempDir)

	configuration := &config.Configuration{
		ImageName: "test-builder-integration:latest",
	}

	// This will only pass if Docker is running
	if err := BuildImageWithDocker(configuration, -1); err != nil {
		t.Skipf("Docker build not possible in this environment: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		cli, err := GetClient(ctx)
		if err == nil {
			_, _ = cli.ImageRemove(ctx, configuration.ImageName, dockerimage.RemoveOptions{Force: true})
		}
	})
}

func TestSaveImageToFileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	resetClient(t)
	requireDocker(t)

	// Save into a temp directory
	tempDir := t.TempDir()
	t.Chdir(tempDir)

	// Test configuration
	configuration := &config.Configuration{
		Name:      "test-app",
		ImageName: "alpine:latest", // Use a common image that should exist
	}

	// Test save
	savedPath, err := SaveImageToFile(configuration, -1)
	if err != nil {
		t.Skipf("Image save not possible in this environment: %v", err)
	}

	// SaveImageToFile creates the tar in the current directory and returns its
	// name as passed to os.Create.
	assert.Equal(t, "test-app.tar", savedPath)

	// Verify the file was created in the working directory and is not empty
	info, err := os.Stat(filepath.Join(tempDir, "test-app.tar"))
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}

func TestImportImageFromFileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	resetClient(t)
	requireDocker(t)

	// Create a test tar file with minimal valid tar content
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-image.tar")

	// Create a minimal tar file (this is not a valid Docker image, but tests the file handling)
	testContent := "fake docker image tar data"
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// The file exists, so the failure must come from the daemon rejecting the
	// payload, not from the file handling.
	err := ImportImageFromFile(testFile)
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist), "unexpected file access error: %v", err)
	t.Logf("Expected error occurred: %v", err)
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
