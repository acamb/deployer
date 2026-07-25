package config

import (
	"os"
	"path/filepath"
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
ekvs_private_key: "` + tmpKey.Name() + `"
`
	path := writeTempConfig(t, yamlContent)
	defer os.Remove(path)

	cfg, err := ReadConfiguration(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.EkvsEnable || cfg.EkvsServer != "https://ekvs.example.com" ||
		cfg.EkvsProject != "proj" || cfg.EkvsPrivateKey != tmpKey.Name() {
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
	if cfg.EkvsPrivateKey != tmpKey.Name() {
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
private_key: "` + tmpKey.Name() + `"
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
	if cfg.EkvsPrivateKey != tmpKey.Name() {
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
