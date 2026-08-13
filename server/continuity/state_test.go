package continuity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hasUnixPermissions reports whether the filesystem honours unix mode bits.
// Windows does not, so the 0600 assertions are skipped there: the server only
// ever runs on Linux (systemd unit, deb/rpm packages).
func hasUnixPermissions() bool {
	return runtime.GOOS != "windows"
}

func sampleState() *State {
	return &State{
		Project:         "myapp",
		Pool:            "my-app.example.com",
		HealthCheckPath: "/health",
		InternalPort:    "80",
		RemovePrevious:  true,
		AdvertiseBase:   "http://10.0.0.5",
		LastAddress:     "http://10.0.0.5:32768",
	}
}

func TestDirIgnoresRevision(t *testing.T) {
	assert.Equal(t, filepath.Join("/opt/deployer", "myapp", ".continuity"), Dir("/opt/deployer", "myapp"))
}

func TestSaveAndLoadStateRoundTrip(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	state := sampleState()

	require.NoError(t, SaveState(dir, state))

	loaded, err := LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, state, loaded)

	if hasUnixPermissions() {
		info, err := os.Stat(filepath.Join(dir, StateFileName))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestSaveStateOverwritesPreviousContent(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	require.NoError(t, SaveState(dir, sampleState()))

	require.NoError(t, SaveState(dir, &State{Project: "myapp", Pool: "other.example.com"}))

	loaded, err := LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "other.example.com", loaded.Pool)
	assert.Empty(t, loaded.LastAddress)
	assert.Empty(t, loaded.InternalPort)

	// No leftover temporary file from the atomic write.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, StateFileName, entries[0].Name())
}

func TestLoadStateMissingFile(t *testing.T) {
	state, err := LoadState(Dir(t.TempDir(), "myapp"))
	require.NoError(t, err)
	assert.Nil(t, state)
}

func TestLoadStateCorruptedFile(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, StateFileName), []byte("{not json"), 0600))

	state, err := LoadState(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse continuity state")
	assert.Nil(t, state)
}

func TestSaveStateRejectsNil(t *testing.T) {
	err := SaveState(Dir(t.TempDir(), "myapp"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil continuity state")
}

func TestUpdateDeployParamsPreservesLastAddress(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	require.NoError(t, SaveState(dir, sampleState()))

	updated, err := UpdateDeployParams(dir, State{
		Project:         "myapp",
		Pool:            "new-pool.example.com",
		HealthCheckPath: "/healthz",
		InternalPort:    "8080",
		RemovePrevious:  false,
		AdvertiseBase:   "https://10.0.0.6",
		// A caller must not be able to clobber the ownership field.
		LastAddress: "http://ignored:1234",
	})
	require.NoError(t, err)

	assert.Equal(t, "http://10.0.0.5:32768", updated.LastAddress)
	assert.Equal(t, "new-pool.example.com", updated.Pool)
	assert.Equal(t, "/healthz", updated.HealthCheckPath)
	assert.Equal(t, "8080", updated.InternalPort)
	assert.False(t, updated.RemovePrevious)
	assert.Equal(t, "https://10.0.0.6", updated.AdvertiseBase)

	reloaded, err := LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, updated, reloaded)
}

func TestUpdateDeployParamsWithoutExistingState(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	updated, err := UpdateDeployParams(dir, State{
		Project:      "myapp",
		Pool:         "my-app.example.com",
		InternalPort: "80",
		LastAddress:  "http://ignored:1234",
	})
	require.NoError(t, err)
	assert.Empty(t, updated.LastAddress)
	assert.Equal(t, "my-app.example.com", updated.Pool)

	reloaded, err := LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.Equal(t, updated, reloaded)
}

func TestUpdateDeployParamsFailsOnCorruptedState(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	require.NoError(t, os.MkdirAll(dir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, StateFileName), []byte("{not json"), 0600))

	state, err := UpdateDeployParams(dir, State{Project: "myapp"})
	require.Error(t, err)
	assert.Nil(t, state)
}
