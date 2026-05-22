package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadServerConfiguration(t *testing.T) {
	testCases := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		expectError bool
		validate    func(t *testing.T, cfg *ServerConfiguration)
	}{
		{
			name: "Valid config file",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				path := filepath.Join(dir, "config.yaml")
				content := `port: 9090
listenAddress: "127.0.0.1"
workingDirectory: "/tmp/deployer"
hostKeyPath: "/etc/ssh/host_key"
`
				require.NoError(t, os.WriteFile(path, []byte(content), 0600))
				return path
			},
			expectError: false,
			validate: func(t *testing.T, cfg *ServerConfiguration) {
				assert.Equal(t, 9090, cfg.Port)
				assert.Equal(t, "127.0.0.1", cfg.ListenAddress)
				assert.Equal(t, "/tmp/deployer", cfg.WorkingDirectory)
				assert.Equal(t, "/etc/ssh/host_key", cfg.HostKeyPath)
			},
		},
		{
			name: "Default values applied for partial config",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				path := filepath.Join(dir, "partial.yaml")
				require.NoError(t, os.WriteFile(path, []byte("port: 1234\n"), 0600))
				return path
			},
			expectError: false,
			validate: func(t *testing.T, cfg *ServerConfiguration) {
				assert.Equal(t, 1234, cfg.Port)
				assert.Equal(t, "0.0.0.0", cfg.ListenAddress)
				assert.Equal(t, "/opt/deployer", cfg.WorkingDirectory)
			},
		},
		{
			name: "Non-existent file returns error",
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.yaml")
			},
			expectError: true,
		},
		{
			name: "Invalid YAML returns error",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				path := filepath.Join(dir, "bad.yaml")
				require.NoError(t, os.WriteFile(path, []byte("port: [unclosed bracket\n"), 0600))
				return path
			},
			expectError: true,
		},
		{
			name: "Empty file path uses default (non-existent) path",
			setupFunc: func(t *testing.T) string {
				return ""
			},
			expectError: true, // default "server_config.yaml" won't exist
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setupFunc(t)
			cfg, err := ReadServerConfiguration(path)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tc.validate != nil {
					tc.validate(t, cfg)
				}
			}
		})
	}
}

func TestCreateSampleConfig(t *testing.T) {
	testCases := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		expectError bool
		validate    func(t *testing.T, path string)
	}{
		{
			name: "Creates valid config file",
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "sample.yaml")
			},
			expectError: false,
			validate: func(t *testing.T, path string) {
				assert.FileExists(t, path)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Contains(t, string(data), "port:")
				assert.Contains(t, string(data), "listenAddress:")
			},
		},
		{
			name: "Non-existent directory returns error",
			setupFunc: func(t *testing.T) string {
				return "/nonexistent/dir/sample.yaml"
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setupFunc(t)
			err := CreateSampleConfig(path)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.validate != nil {
					tc.validate(t, path)
				}
			}
		})
	}
}
