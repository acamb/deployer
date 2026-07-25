package config

import (
	"os"
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
