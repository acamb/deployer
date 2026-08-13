package continuity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const sampleContinuityConfig = `host: http://continuity.example.com
port: 8090
default_pool: my-app.example.com
auth_key: /home/user/.ssh/continuity_key
`

func TestWriteProjectConfigPathARewritesAuthKey(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	cfgPath, err := WriteProjectConfig(dir, []byte(sampleContinuityConfig), []byte("PRIVATE KEY"))
	require.NoError(t, err)

	absDir, err := filepath.Abs(dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(absDir, ConfigFileName), cfgPath)

	keyPath := filepath.Join(absDir, KeyFileName)
	keyBytes, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, "PRIVATE KEY", string(keyBytes))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &document))
	// auth_key points at the local copy, with an absolute path: continuity
	// does no `~` expansion and resolves the path on this machine.
	assert.Equal(t, keyPath, document["auth_key"])
	assert.True(t, filepath.IsAbs(document["auth_key"].(string)))
	// The other entries survive the rewrite untouched.
	assert.Equal(t, "http://continuity.example.com", document["host"])
	assert.Equal(t, 8090, document["port"])
	assert.Equal(t, "my-app.example.com", document["default_pool"])

	if hasUnixPermissions() {
		keyInfo, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
		cfgInfo, err := os.Stat(cfgPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), cfgInfo.Mode().Perm())
	}
}

func TestWriteProjectConfigPathAAddsMissingAuthKey(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	cfgPath, err := WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), []byte("PRIVATE KEY"))
	require.NoError(t, err)

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &document))
	assert.Equal(t, filepath.Join(filepath.Dir(cfgPath), KeyFileName), document["auth_key"])
}

func TestWriteProjectConfigPathBKeepsConfigVerbatim(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	cfgPath, err := WriteProjectConfig(dir, []byte(sampleContinuityConfig), nil)
	require.NoError(t, err)

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, sampleContinuityConfig, string(data))

	_, err = os.Stat(filepath.Join(filepath.Dir(cfgPath), KeyFileName))
	assert.True(t, os.IsNotExist(err), "path B must not write any key file")

	if hasUnixPermissions() {
		info, err := os.Stat(cfgPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestWriteProjectConfigRejectsEmptyConfig(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	for _, cfgBytes := range [][]byte{nil, []byte("   \n\t")} {
		cfgPath, err := WriteProjectConfig(dir, cfgBytes, []byte("PRIVATE KEY"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no continuity configuration")
		assert.Empty(t, cfgPath)
	}
}

func TestWriteProjectConfigRejectsInvalidYaml(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	cfgPath, err := WriteProjectConfig(dir, []byte("host: [unterminated\n"), []byte("PRIVATE KEY"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse the continuity configuration")
	assert.Empty(t, cfgPath)
}

func TestWriteProjectConfigPreservesState(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")
	require.NoError(t, SaveState(dir, sampleState()))

	_, err := WriteProjectConfig(dir, []byte(sampleContinuityConfig), []byte("PRIVATE KEY"))
	require.NoError(t, err)

	loaded, err := LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "http://10.0.0.5:32768", loaded.LastAddress)
}

func TestWriteProjectConfigOverwritesPreviousFiles(t *testing.T) {
	dir := Dir(t.TempDir(), "myapp")

	_, err := WriteProjectConfig(dir, []byte(sampleContinuityConfig), []byte("OLD KEY"))
	require.NoError(t, err)
	cfgPath, err := WriteProjectConfig(dir, []byte("host: http://other.example.com\n"), []byte("NEW KEY"))
	require.NoError(t, err)

	keyBytes, err := os.ReadFile(filepath.Join(filepath.Dir(cfgPath), KeyFileName))
	require.NoError(t, err)
	assert.Equal(t, "NEW KEY", string(keyBytes))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var document map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &document))
	assert.Equal(t, "http://other.example.com", document["host"])
	assert.NotContains(t, document, "default_pool")

	// The atomic writes leave no temporary file behind.
	entries, err := os.ReadDir(filepath.Dir(cfgPath))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	assert.ElementsMatch(t, []string{ConfigFileName, KeyFileName}, names)
}
