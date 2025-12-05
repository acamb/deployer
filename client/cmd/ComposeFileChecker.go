package main

import (
	"deployer/client/config"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	ContainerName string `yaml:"container_name"`
}

func CheckComposeFileForServiceNameCoherence(configuration *config.Configuration) {
	f, err := os.Open(configuration.ComposePath)
	if err != nil {
		log.Fatalf("Error opening compose file '%s': %v", configuration.ComposePath, err)
	}
	defer f.Close()

	var cf composeFile
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cf); err != nil {
		log.Fatalf("Error parsing YAML in compose file '%s': %v", configuration.ComposePath, err)
	}

	if cf.Services == nil || len(cf.Services) == 0 {
		log.Fatalf("No services found in compose file")
	}
	svc, ok := cf.Services[configuration.Name]
	if !ok {
		log.Fatalf("Service '%s' not found in the compose file; revisions require a service with the same name specified in the configuration file", configuration.Name)
	}

	if svc.ContainerName == "" {
		log.Fatalf("The service '%s' doesn't define 'container_name' in compose file", configuration.Name)
	}
	if svc.ContainerName != configuration.Name {
		log.Fatalf("Inconsistency: `container_name`='%s' but expected '%s' for service '%s' in compose file '%s'",
			svc.ContainerName, configuration.Name, configuration.Name, configuration.ComposePath)
	}
}
