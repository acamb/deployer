package config

import (
	"fmt"
	"io"
	"log"
	"os"
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
		return fmt.Errorf("ekvs_enable is true but ekvs_private_key is not set")
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
##container environment. When ekvs_enable is true, ekvs_server, ekvs_project
##and ekvs_private_key are required.
#ekvs_enable: false
#ekvs_server: 'https://ekvs.example.com'
#ekvs_project: 'my-project'
#ekvs_private_key: '/path/to/ekvs_private_key'
`))
	return err
}
