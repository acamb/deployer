package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Error creating temp config: %v", err)
	}
	defer tmpfile.Close()
	_, err = tmpfile.WriteString(content)
	if err != nil {
		t.Fatalf("Error writing test config: %v", err)
	}
	return tmpfile.Name()
}

func TestReadConfiguration_Success(t *testing.T) {
	yamlContent := `
host: "127.0.0.1"
port: 1234
name: "test"
image_name: "myimage"
private_key: "key"
compose_file_path: "docker-compose.yml"
build_method: "docker"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("error parsing: %v", err)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 1234 || cfg.Name != "test" {
		t.Errorf("Error reading connection parameters, read: %+v", cfg)
	}
	if cfg.ImageName != "myimage:latest" {
		t.Errorf("Error reading image_name value, read : %s", cfg.ImageName)
	}
	if cfg.BuildMethod != Docker {
		t.Errorf("Error reading build_method, read: %s", cfg.BuildMethod)
	}
}

func TestReadConfiguration_Defaults(t *testing.T) {
	yamlContent := `
name: "abc"
build_method: "compose"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("errore parsing: %v", err)
	}
	if cfg.Host != "localhost" || cfg.Port != 7676 {
		t.Errorf("Expecting 'localhost' and 7676 port as default values, but got: %+v", cfg)
	}
	if cfg.ImageName != "abc:latest" {
		t.Errorf("Expecting 'abc:lastest' as default image name, but got: %s", cfg.ImageName)
	}
	if cfg.ComposePath != "compose.yml" {
		t.Errorf("Expecting 'compose.yaml' as default compose_file_path, but got: %s", cfg.ComposePath)
	}
}

func TestReadConfiguration_InvalidBuildMethod(t *testing.T) {
	yamlContent := `
name: "abc"
build_method: "invalid"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	_, err := ReadConfiguration(path)
	if err == nil {
		t.Fatal("Expecting error for invalid build_method, but got none")
	}
}

func TestReadConfiguration_FileNotFound(t *testing.T) {
	_, err := ReadConfiguration("nonexistent.yaml")
	if err == nil {
		t.Fatal("Expecting error for non-existent file, but got none")
	}
}

func TestReadConfiguration_EkvsFieldsParsed(t *testing.T) {
	tmpKey, err := os.CreateTemp("", "ekvs-key-*")
	if err != nil {
		t.Fatalf("cannot create temp key: %v", err)
	}
	_, _ = tmpKey.WriteString("dummy-key")
	_ = tmpKey.Close()
	defer os.Remove(tmpKey.Name())

	yamlContent := `
name: "ekvs-app"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_project: "proj"
ekvs_private_key: "` + filepath.ToSlash(tmpKey.Name()) + `"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.EkvsEnable || cfg.EkvsServer != "https://ekvs.example.com" ||
		cfg.EkvsProject != "proj" ||
		filepath.ToSlash(cfg.EkvsPrivateKey) != filepath.ToSlash(tmpKey.Name()) {
		t.Errorf("EKVS fields not parsed correctly: %+v", cfg)
	}
}

func TestReadConfiguration_EkvsEnabledMissingServer(t *testing.T) {
	yamlContent := `
name: "ekvs-app"
ekvs_enable: true
ekvs_project: "proj"
ekvs_private_key: "/tmp/whatever"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	_, err := ReadConfiguration(path)
	if err == nil {
		t.Fatal("Expecting error for missing ekvs_server")
	}
}

func TestReadConfiguration_EkvsEnabledMissingProject(t *testing.T) {
	yamlContent := `
name: "ekvs-app"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_private_key: "/tmp/whatever"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	_, err := ReadConfiguration(path)
	if err == nil {
		t.Fatal("Expecting error for missing ekvs_project")
	}
}

func TestReadConfiguration_EkvsEnabledMissingKeyFile(t *testing.T) {
	yamlContent := `
name: "ekvs-app"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_project: "proj"
ekvs_private_key: "/nonexistent/path/to/ekvs_key"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	_, err := ReadConfiguration(path)
	if err == nil {
		t.Fatal("Expecting error for unreadable ekvs_private_key file")
	}
}

func TestReadConfiguration_EkvsDisabled_NoValidation(t *testing.T) {
	// When ekvs_enable is false, other ekvs_* fields are not required.
	yamlContent := `
name: "no-ekvs-app"
ekvs_enable: false
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EkvsEnable {
		t.Errorf("EkvsEnable should be false")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}
	cases := map[string]string{
		"~":         home,
		"~/":        home + "/",
		"~/foo/bar": home + "/foo/bar",
		"/abs/path": "/abs/path",
		"relative":  "relative",
		"~user/x":   "~user/x", // only ~ and ~/ are expanded
		"":          "",
	}
	for in, want := range cases {
		got, err := expandHome(in)
		if err != nil {
			t.Fatalf("expandHome(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadConfiguration_ExpandsHomeInKeyPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}
	// Create a temp key inside HOME so ekvs validation passes.
	tmpKey, err := os.CreateTemp(home, "ekvs-key-*")
	if err != nil {
		t.Fatalf("cannot create temp key in home: %v", err)
	}
	_, _ = tmpKey.WriteString("dummy")
	_ = tmpKey.Close()
	defer os.Remove(tmpKey.Name())

	rel := "~/" + filepath.Base(tmpKey.Name())
	yamlContent := `
name: "app"
private_key: "~/.ssh/id_rsa"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_project: "proj"
ekvs_private_key: "` + rel + `"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PrivateKey != home+"/.ssh/id_rsa" {
		t.Errorf("private_key not expanded, got: %q", cfg.PrivateKey)
	}
	// Compare with normalized separators: expandHome concatenates instead of
	// using filepath.Join, so on Windows it yields "C:\Users\me/file". The
	// path still resolves; only its spelling differs.
	if filepath.ToSlash(cfg.EkvsPrivateKey) != filepath.ToSlash(tmpKey.Name()) {
		t.Errorf("ekvs_private_key not expanded correctly, got %q want %q", cfg.EkvsPrivateKey, tmpKey.Name())
	}
}

func TestReadConfiguration_EkvsFallbackToPrivateKey(t *testing.T) {
	tmpKey, err := os.CreateTemp("", "pk-*")
	if err != nil {
		t.Fatalf("cannot create temp key: %v", err)
	}
	_, _ = tmpKey.WriteString("dummy")
	_ = tmpKey.Close()
	defer os.Remove(tmpKey.Name())

	yamlContent := `
name: "app"
private_key: "` + filepath.ToSlash(tmpKey.Name()) + `"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_project: "proj"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.ToSlash(cfg.EkvsPrivateKey) != filepath.ToSlash(tmpKey.Name()) {
		t.Errorf("expected ekvs_private_key to fall back to private_key %q, got %q", tmpKey.Name(), cfg.EkvsPrivateKey)
	}
}

func TestReadConfiguration_EkvsEnabledNoKeysAtAll(t *testing.T) {
	// When neither ekvs_private_key nor private_key is set, EKVS validation
	// must fall back to the auto-discovered default SSH key. If no such key
	// exists on this system, the test is skipped (behavior would be an error).
	discovered, discoverErr := FindDefaultSSHKey()

	yamlContent := `
name: "app"
ekvs_enable: true
ekvs_server: "https://ekvs.example.com"
ekvs_project: "proj"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if discoverErr != nil {
		if err == nil {
			t.Fatal("Expecting error when no keys are set and no default SSH key exists")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error with auto-discovered SSH key: %v", err)
	}
	if cfg.EkvsPrivateKey != discovered {
		t.Errorf("expected ekvs_private_key to fall back to auto-discovered SSH key %q, got %q", discovered, cfg.EkvsPrivateKey)
	}
}

// writeContinuityFile writes a native Continuity CLI configuration file, the
// one whose contents the client forwards to the server.
func writeContinuityFile(t *testing.T, dir string, name string, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("Error writing continuity config %s: %v", path, err)
	}
	return path
}

func TestValidateContinuity(t *testing.T) {
	dir := t.TempDir()

	keyPath := writeContinuityFile(t, dir, "continuity_key", "PRIVATE KEY")
	valid := writeContinuityFile(t, dir, "valid.yaml",
		"host: http://continuity.example.com\nport: 8090\ndefault_pool: pool\nauth_key: /opt/deployer/continuity_key\n")
	hostNoScheme := writeContinuityFile(t, dir, "host-no-scheme.yaml",
		"host: continuity.example.com\nport: 8090\ndefault_pool: pool\nauth_key: /opt/deployer/k\n")
	tildeAuthKey := writeContinuityFile(t, dir, "tilde-auth-key.yaml",
		"host: http://continuity.example.com\nport: 8090\ndefault_pool: pool\nauth_key: ~/.ssh/continuity_key\n")
	relativeAuthKey := writeContinuityFile(t, dir, "relative-auth-key.yaml",
		"host: http://continuity.example.com\nport: 8090\ndefault_pool: pool\nauth_key: keys/continuity_key\n")
	noAuthKey := writeContinuityFile(t, dir, "no-auth-key.yaml",
		"host: http://continuity.example.com\nport: 8090\ndefault_pool: pool\n")
	noDefaultPool := writeContinuityFile(t, dir, "no-default-pool.yaml",
		"host: http://continuity.example.com\nport: 8090\nauth_key: /opt/deployer/k\n")
	noHost := writeContinuityFile(t, dir, "no-host.yaml",
		"port: 8090\ndefault_pool: pool\nauth_key: /opt/deployer/k\n")

	// baseConfig is a valid Path B configuration: no local key, auth_key
	// inside the forwarded file already points at the server's filesystem.
	baseConfig := func() *Configuration {
		return &Configuration{
			ContinuityEnable:        true,
			ContinuityConfig:        valid,
			ContinuityInternalPort:  "8080",
			ContinuityPool:          "mypool",
			ContinuityAdvertiseBase: "http://10.0.0.5",
		}
	}

	testCases := []struct {
		name    string
		mutate  func(config *Configuration)
		wantErr string // empty means success is expected
	}{
		{"PathB", func(c *Configuration) {}, ""},
		{"PathA", func(c *Configuration) { c.ContinuityPrivateKey = keyPath }, ""},
		{"Disabled", func(c *Configuration) {
			c.ContinuityEnable = false
			c.ContinuityConfig = ""
			c.ContinuityInternalPort = ""
		}, ""},
		{"MissingConfig", func(c *Configuration) { c.ContinuityConfig = "" },
			"continuity_config is not set"},
		{"ConfigDoesNotExist", func(c *Configuration) { c.ContinuityConfig = filepath.Join(dir, "missing.yaml") },
			"cannot access continuity_config"},
		{"ConfigIsDirectory", func(c *Configuration) { c.ContinuityConfig = dir },
			"is a directory"},
		{"MissingInternalPort", func(c *Configuration) { c.ContinuityInternalPort = "" },
			"continuity_internal_port is not set"},
		{"InternalPortNotNumeric", func(c *Configuration) { c.ContinuityInternalPort = "http" },
			"not a valid port number"},
		{"InternalPortOutOfRange", func(c *Configuration) { c.ContinuityInternalPort = "70000" },
			"not a valid port number"},
		{"HealthCheckPathWithoutSlash", func(c *Configuration) { c.ContinuityHealthCheckPath = "health" },
			"must start with '/'"},
		{"HealthCheckPathEmptyIsAllowed", func(c *Configuration) { c.ContinuityHealthCheckPath = "" }, ""},
		{"AdvertiseBaseMissing", func(c *Configuration) { c.ContinuityAdvertiseBase = "" },
			"continuity_advertise_base is not set"},
		{"AdvertiseBaseWithoutScheme", func(c *Configuration) { c.ContinuityAdvertiseBase = "10.0.0.5" },
			"must start with http:// or https://"},
		{"AdvertiseBaseWithPort", func(c *Configuration) { c.ContinuityAdvertiseBase = "http://10.0.0.5:80" },
			"must not contain a port"},
		{"AdvertiseBaseWithPath", func(c *Configuration) { c.ContinuityAdvertiseBase = "http://10.0.0.5/app" },
			"must not contain a path"},
		{"AdvertiseBaseValid", func(c *Configuration) { c.ContinuityAdvertiseBase = "https://app.example.com" }, ""},
		{"HostWithoutScheme", func(c *Configuration) { c.ContinuityConfig = hostNoScheme },
			"must include the scheme"},
		{"HostMissing", func(c *Configuration) { c.ContinuityConfig = noHost },
			"does not set 'host'"},
		{"TildeAuthKeyInPathB", func(c *Configuration) { c.ContinuityConfig = tildeAuthKey },
			"does not expand '~'"},
		{"RelativeAuthKeyInPathB", func(c *Configuration) { c.ContinuityConfig = relativeAuthKey },
			"must be an absolute path"},
		{"MissingAuthKeyInPathB", func(c *Configuration) { c.ContinuityConfig = noAuthKey },
			"has no 'auth_key'"},
		{"TildeAuthKeyIgnoredInPathA", func(c *Configuration) {
			// Path A rewrites auth_key on the server, so its current value
			// is irrelevant.
			c.ContinuityConfig = tildeAuthKey
			c.ContinuityPrivateKey = keyPath
		}, ""},
		{"NoPoolAndNoDefaultPool", func(c *Configuration) {
			c.ContinuityConfig = noDefaultPool
			c.ContinuityPool = ""
		}, "no 'default_pool'"},
		{"DefaultPoolCoversEmptyPool", func(c *Configuration) { c.ContinuityPool = "" }, ""},
		{"PrivateKeyDoesNotExist", func(c *Configuration) { c.ContinuityPrivateKey = filepath.Join(dir, "missing_key") },
			"cannot access continuity_private_key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := baseConfig()
			tc.mutate(config)
			err := validateContinuity(config)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Expecting success, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Expecting error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Expecting error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateAdvertiseBase_TrimsTrailingSlash(t *testing.T) {
	config := &Configuration{ContinuityAdvertiseBase: "http://10.0.0.5/"}
	if err := validateAdvertiseBase(config); err != nil {
		t.Fatalf("a trailing slash should be normalized, got error: %v", err)
	}
	if config.ContinuityAdvertiseBase != "http://10.0.0.5" {
		t.Errorf("expected trailing slash to be trimmed, got %q", config.ContinuityAdvertiseBase)
	}
}

func TestReadConfiguration_ContinuityFieldsParsed(t *testing.T) {
	dir := t.TempDir()
	continuityFile := writeContinuityFile(t, dir, "continuity.yaml",
		"host: http://continuity.example.com\nport: 8090\ndefault_pool: pool\nauth_key: /opt/deployer/continuity_key\n")
	keyPath := writeContinuityFile(t, dir, "continuity_key", "PRIVATE KEY")

	yamlContent := `
name: "app"
continuity_enable: true
continuity_config: "` + filepath.ToSlash(continuityFile) + `"
continuity_private_key: "` + filepath.ToSlash(keyPath) + `"
continuity_pool: "mypool"
continuity_health_check_path: "/healthz"
continuity_internal_port: "8080"
continuity_remove_previous: true
continuity_advertise_base: "https://app.example.com"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ContinuityEnable || !cfg.ContinuityRemovePrevious {
		t.Errorf("continuity boolean flags not parsed: %+v", cfg)
	}
	if cfg.ContinuityPool != "mypool" || cfg.ContinuityHealthCheckPath != "/healthz" || cfg.ContinuityInternalPort != "8080" {
		t.Errorf("continuity fields not parsed correctly: %+v", cfg)
	}
	if cfg.ContinuityAdvertiseBase != "https://app.example.com" {
		t.Errorf("continuity_advertise_base not parsed, got %q", cfg.ContinuityAdvertiseBase)
	}
}

func TestReadConfiguration_RevisionsRemovePrevious(t *testing.T) {
	path := writeTempConfig(t, "name: \"app\"\nenable_revisions: true\nrevisions_remove_previous: true\n")
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.RevisionsRemovePrevious {
		t.Errorf("expected RevisionsRemovePrevious to be true, got %+v", cfg)
	}
}

func TestReadConfiguration_RevisionsRemovePreviousDefaultsFalse(t *testing.T) {
	path := writeTempConfig(t, "name: \"app\"\nenable_revisions: true\n")
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RevisionsRemovePrevious {
		t.Errorf("expected RevisionsRemovePrevious to default to false, got %+v", cfg)
	}
}

func TestReadConfiguration_ExpandsHomeInContinuityPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	continuityFile, err := os.CreateTemp(home, "continuity-*.yaml")
	if err != nil {
		t.Skipf("cannot create temp file in home directory: %v", err)
	}
	defer os.Remove(continuityFile.Name())
	if _, err := continuityFile.WriteString("host: http://continuity.example.com\ndefault_pool: pool\nauth_key: /opt/deployer/k\n"); err != nil {
		t.Fatalf("Error writing continuity config: %v", err)
	}
	continuityFile.Close()

	keyFile, err := os.CreateTemp(home, "continuity-key-*")
	if err != nil {
		t.Skipf("cannot create temp key in home directory: %v", err)
	}
	defer os.Remove(keyFile.Name())
	keyFile.Close()

	yamlContent := `
name: "app"
continuity_enable: true
continuity_config: "~/` + filepath.Base(continuityFile.Name()) + `"
continuity_private_key: "~/` + filepath.Base(keyFile.Name()) + `"
continuity_pool: "mypool"
continuity_internal_port: "8080"
continuity_advertise_base: "http://10.0.0.5"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Compare with normalized separators: expandHome concatenates instead of
	// using filepath.Join, so on Windows it yields "C:\Users\me/file". The
	// path still resolves; only its spelling differs.
	if filepath.ToSlash(cfg.ContinuityConfig) != filepath.ToSlash(continuityFile.Name()) {
		t.Errorf("continuity_config not expanded correctly, got %q want %q", cfg.ContinuityConfig, continuityFile.Name())
	}
	if filepath.ToSlash(cfg.ContinuityPrivateKey) != filepath.ToSlash(keyFile.Name()) {
		t.Errorf("continuity_private_key not expanded correctly, got %q want %q", cfg.ContinuityPrivateKey, keyFile.Name())
	}
}
