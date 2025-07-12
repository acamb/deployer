package config

import (
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"strings"
)

type Configuration struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Name       string `yaml:"name"`
	ImageName  string `yaml:"image_name"`
	PrivateKey string `yaml:"private_key"`
}

func ReadConfiguration(filePath string) (*Configuration, error) {
	config := &Configuration{
		Host: "localhost",
		Port: 7676,
		Name: "default",
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

func WriteSampleConfiguration(config *Configuration) error {
	file, err := os.Create("config.yaml")
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	_, err = file.Write(data)

	return err
}
