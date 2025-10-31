package config

import (
	"fmt"
	"io"
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
	Host        string      `yaml:"host"`
	Port        int         `yaml:"port"`
	Name        string      `yaml:"name"`
	ImageName   string      `yaml:"image_name"`
	PrivateKey  string      `yaml:"private_key"`
	ComposePath string      `yaml:"compose_file_path"`
	BuildMethod BuildMethod `yaml:"build_method"`
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

	if !strings.Contains(config.ImageName, ":") {
		config.ImageName += ":latest"
	}

	return config, nil
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
`))
	return err
}
