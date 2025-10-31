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
