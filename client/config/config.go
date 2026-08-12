package config

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type BuildMethod string

const (
	Docker  BuildMethod = "docker"
	Compose BuildMethod = "compose"
)

func (b *BuildMethod) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch s {
	case string(Docker), string(Compose):
		*b = BuildMethod(s)
		return nil
	default:
		return fmt.Errorf("BuildMethod not valid: %s", s)
	}
}

type Configuration struct {
	Host            string      `yaml:"host"`
	Port            int         `yaml:"port"`
	Name            string      `yaml:"name"`
	ImageName       string      `yaml:"image_name"`
	PrivateKey      string      `yaml:"private_key"`
	ComposePath     string      `yaml:"compose_file_path"`
	BuildMethod     BuildMethod `yaml:"build_method"`
	EnableRevisions bool        `yaml:"enable_revisions"`

	EkvsEnable     bool   `yaml:"ekvs_enable"`
	EkvsServer     string `yaml:"ekvs_server"`
	EkvsProject    string `yaml:"ekvs_project"`
	EkvsPrivateKey string `yaml:"ekvs_private_key"`

	// ContinuityPrivateKey is fully optional and has no fallback (unlike
	// EkvsPrivateKey): when left empty, it means the auth_key referenced
	// inside ContinuityConfig already points to a key present on the
	// server, placed there manually by an administrator.
	ContinuityEnable          bool   `yaml:"continuity_enable"`
	ContinuityConfig          string `yaml:"continuity_config"`
	ContinuityPrivateKey      string `yaml:"continuity_private_key"`
	ContinuityPool            string `yaml:"continuity_pool"`
	ContinuityHealthCheckPath string `yaml:"continuity_health_check_path"`
	ContinuityInternalPort    string `yaml:"continuity_internal_port"`
	ContinuityRemovePrevious  bool   `yaml:"continuity_remove_previous"`
}

func ReadConfiguration(filePath string) (*Configuration, error) {
	config := &Configuration{
		Host:        "localhost",
		Port:        7676,
		Name:        "default",
		ComposePath: "compose.yml",
	}

	if filePath == "" {
		filePath = "config.yaml"
	}

	err := readYaml(filePath, config)
	if err != nil {
		return nil, err
	}

	if config.PrivateKey != "" {
		expanded, err := expandHome(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand private_key path %q: %v", config.PrivateKey, err)
		}
		config.PrivateKey = expanded
	}
	if config.EkvsPrivateKey != "" {
		expanded, err := expandHome(config.EkvsPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand ekvs_private_key path %q: %v", config.EkvsPrivateKey, err)
		}
		config.EkvsPrivateKey = expanded
	}
	if config.ContinuityConfig != "" {
		expanded, err := expandHome(config.ContinuityConfig)
		if err != nil {
			return nil, fmt.Errorf("cannot expand continuity_config path %q: %v", config.ContinuityConfig, err)
		}
		config.ContinuityConfig = expanded
	}
	if config.ContinuityPrivateKey != "" {
		expanded, err := expandHome(config.ContinuityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand continuity_private_key path %q: %v", config.ContinuityPrivateKey, err)
		}
		config.ContinuityPrivateKey = expanded
	}

	if config.ImageName == "" {
		config.ImageName = config.Name
	}

	if !strings.Contains(config.ImageName, ":") && !config.EnableRevisions {
		config.ImageName += ":latest"
	} else if strings.Contains(config.ImageName, ":") && config.EnableRevisions {
		log.Fatal("Error: enable_revisions cannot be true when image_name contains a tag. Please remove the tag from image_name.")
	}

	if err := validateEkvs(config); err != nil {
		return nil, err
	}

	if err := validateContinuity(config); err != nil {
		return nil, err
	}

	return config, nil
}

func validateEkvs(config *Configuration) error {
	if !config.EkvsEnable {
		return nil
	}
	if strings.TrimSpace(config.EkvsServer) == "" {
		return fmt.Errorf("ekvs_enable is true but ekvs_server is not set")
	}
	if strings.TrimSpace(config.EkvsProject) == "" {
		return fmt.Errorf("ekvs_enable is true but ekvs_project is not set")
	}
	if strings.TrimSpace(config.EkvsPrivateKey) == "" {
		if strings.TrimSpace(config.PrivateKey) != "" {
			log.Printf("ekvs_private_key not set: using private_key %q as EKVS key. Set 'ekvs_private_key' in the config file to use a dedicated key.", config.PrivateKey)
			config.EkvsPrivateKey = config.PrivateKey
		} else {
			discovered, err := FindDefaultSSHKey()
			if err != nil {
				return fmt.Errorf("ekvs_enable is true but no private key is available: %v", err)
			}
			log.Printf("ekvs_private_key and private_key not set: using auto-discovered SSH key %q as EKVS key. Set 'ekvs_private_key' in the config file to use a dedicated key.", discovered)
			config.EkvsPrivateKey = discovered
		}
	}
	info, err := os.Stat(config.EkvsPrivateKey)
	if err != nil {
		return fmt.Errorf("cannot access ekvs_private_key file %q: %v", config.EkvsPrivateKey, err)
	}
	if info.IsDir() {
		return fmt.Errorf("ekvs_private_key %q is a directory, expected a file", config.EkvsPrivateKey)
	}

	f, err := os.Open(config.EkvsPrivateKey)
	if err != nil {
		return fmt.Errorf("cannot read ekvs_private_key file %q: %v", config.EkvsPrivateKey, err)
	}
	_ = f.Close()
	return nil
}

// validateContinuity validates the Continuity integration fields. Unlike
// validateEkvs, ContinuityPrivateKey has no fallback: an empty value is a
// deliberate choice meaning the auth_key referenced inside ContinuityConfig
// already points to a key present on the server (Path B), so no local file
// is required or checked here in that case.
func validateContinuity(config *Configuration) error {
	if !config.ContinuityEnable {
		return nil
	}
	if strings.TrimSpace(config.ContinuityConfig) == "" {
		return fmt.Errorf("continuity_enable is true but continuity_config is not set")
	}
	if err := checkReadableFile(config.ContinuityConfig, "continuity_config"); err != nil {
		return err
	}

	if strings.TrimSpace(config.ContinuityPrivateKey) == "" {
		return nil
	}
	if err := checkReadableFile(config.ContinuityPrivateKey, "continuity_private_key"); err != nil {
		return err
	}
	return nil
}

// checkReadableFile verifies that path exists, is not a directory, and can
// be opened for reading. fieldName is used to produce a descriptive error.
func checkReadableFile(path string, fieldName string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access %s file %q: %v", fieldName, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %q is a directory, expected a file", fieldName, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read %s file %q: %v", fieldName, path, err)
	}
	_ = f.Close()
	return nil
}

func readYaml(path string, config *Configuration) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, config)
}

var DefaultSSHKeyTypes = []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}

func FindDefaultSSHKey() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	for _, keyType := range DefaultSSHKeyTypes {
		keyPath := filepath.Join(sshDir, keyType)
		if _, err := os.Stat(keyPath); err == nil {
			return keyPath, nil
		}
	}
	return "", fmt.Errorf("no SSH private key found in %s (tried: %v)", sshDir, DefaultSSHKeyTypes)
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return home + path[1:], nil
}

func WriteSampleConfiguration() error {
	file, err := os.Create("config.yaml")
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write([]byte(`
host: localhost
port: 7676
name: myapp
image_name: myapp:latest
#private_key: '~/.ssh/id_rsa'
#compose_file_path: 'compose.yml'
##build_method values: 'docker' or 'compose'.
##If not set, it will use 'docker' when Dockerfile is present, otherwise 'compose'.
#build_method: 'docker'
#enable_revisions will manage different revisions for the same project, useful for zero-downtime deployments and rollbacks.
#enable_revisions: true
##EKVS integration (optional): inject secrets from an EKVS server into the
##container environment. When ekvs_enable is true, ekvs_server and
##ekvs_project are required. ekvs_private_key is optional: if omitted, the
##value of private_key will be used as the EKVS key.
##Paths accept a leading '~' or '~/' which are expanded to the user's home.
#ekvs_enable: false
#ekvs_server: 'https://ekvs.example.com'
#ekvs_project: 'my-project'
#ekvs_private_key: '~/.ssh/ekvs_key'
##Continuity integration (optional): register the deployed container as a
##backend on a Continuity load balancer pool. When continuity_enable is
##true, continuity_config is required: it must point to a Continuity CLI
##configuration file (host/port/default_pool/auth_key).
##continuity_private_key is optional and has NO fallback (unlike
##ekvs_private_key):
## - if set, the key is read here and sent to the server, which will copy
##   it into the project's working directory and rewrite auth_key in the
##   forwarded continuity_config to point at it;
## - if left empty, auth_key in continuity_config is assumed to already
##   point to a key present on the server, placed there manually.
#continuity_enable: false
#continuity_config: './continuity-client.yaml'
#continuity_private_key: '~/.ssh/continuity_key'
#continuity_pool: 'my-app.example.com'
#continuity_health_check_path: '/health'
#continuity_internal_port: '8080'
#continuity_remove_previous: true
`))
	return err
}
