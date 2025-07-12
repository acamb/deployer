package config

import (
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

type ServerConfiguration struct {
	Port             int    `yaml:"port"`
	ListenAddress    string `yaml:"listenAddress"`
	WorkingDirectory string `yaml:"workingDirectory"`
	HostKeyPath      string `yaml:"hostKeyPath"`
}

func ReadServerConfiguration(filePath string) (*ServerConfiguration, error) {
	config := &ServerConfiguration{
		Port:             8080,
		ListenAddress:    "0.0.0.0",
		WorkingDirectory: "/opt/deployer",
	}
	if filePath == "" {
		filePath = "server_config.yaml"
	}
	err := readYaml(filePath, config)
	return config, err
}

func readYaml(path string, config *ServerConfiguration) error {
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

func CreateSampleConfig(filePath string) error {
	var path = "deploy"
	if filePath == "" {
		path = filePath
	}
	config := &ServerConfiguration{
		Port:             7676,
		ListenAddress:    "0.0.0.0",
		WorkingDirectory: path,
		HostKeyPath:      "/etc/ssh/ssh_host_rsa_key",
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	file, err := os.Create(filePath)
	defer file.Close()
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return err
}
