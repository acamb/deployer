package main

import (
	"deployer/builder"
	"deployer/client"
	"deployer/client/config"
	"github.com/spf13/cobra"
	"log"
	"os"
)

func main() {
	var filePath string
	var configuration *config.Configuration
	var err error
	rootCmd := &cobra.Command{
		Use:   "deployer-client",
		Short: "deploy client",
	}

	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "configuration file path")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmd.Use != "config" {
			configuration, err = config.ReadConfiguration(filePath)
			if err != nil {
				log.Fatalf("Error reading configuration: %v", err)
			}
			err := client.Connect(*configuration)
			if err != nil {
				log.Fatalf("Error connecting to remote server: %v", err)
			}
		}
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Generate a sample configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			sampleConfig := &config.Configuration{
				Host:      "localhost",
				Port:      7676,
				Name:      "default",
				ImageName: "myapp",
			}
			err := config.WriteSampleConfiguration(sampleConfig)
			if err != nil {
				log.Fatalf("Error generating sample configuration: %v", err)
			}
			log.Println("Sample configuration file generated: config.yaml")
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "build",
		Short: "Build Docker image locally",
		Run: func(cmd *cobra.Command, args []string) {
			err = builder.BuildImage(configuration)
			if err != nil {
				log.Fatalf("Error building image: %v", err)
			}
			log.Println("Docker image built successfully")
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Export Docker image to .tar file",
		Run: func(cmd *cobra.Command, args []string) {
			file, err := builder.SaveImageToFile(configuration)
			if err != nil {
				log.Fatalf("Error saving image to file: %v", err)
			} else {
				log.Printf("Docker image saved to file: %s", file.Name())
			}
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			log.Default().Println("Starting remote container...")
			if err := client.StartContainer(configuration.Name); err != nil {
				log.Fatalf("Error starting container: %v", err)
			} else {
				log.Println("Container started successfully")
			}

		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			log.Default().Println("Stopping remote container...")
			if err := client.StopContainer(configuration.Name); err != nil {
				log.Fatalf("Error stopping container: %v", err)
			} else {
				log.Println("Container stopped successfully")
			}

		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			log.Default().Println("Restarting remote container...")
			if err := client.RestartContainer(configuration.Name); err != nil {
				log.Fatalf("Error restarting container: %v", err)
			} else {
				log.Println("Container restarting successfully")
			}

		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "deploy",
		Short: "Deploy and starts the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			if err := DeployImage(configuration); err != nil {
				log.Fatalf("Error deploying container: %v", err)
			} else {
				log.Println("Container deploying successfully")
			}

		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "logs",
		Short: "Prints the logs of the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			channel, err := client.Logs(configuration.Name)
			if err != nil {
				log.Fatalf("Error reading logs for container: %v", err)
			}

			for {
				select {
				case logMessage, ok := <-channel:
					if !ok {
						log.Println("No more logs to read")
						return
					}
					log.Println(logMessage)
				}
			}

		},
	})
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func DeployImage(configuration *config.Configuration) error {

	var outputFile *os.File
	//check if dockerfile exists
	if _, err := os.Stat("Dockerfile"); os.IsNotExist(err) {
		log.Println("Dockerfile not found, using only compose.yml...")
	} else {
		log.Default().Println("Building docker image...")
		if err := builder.BuildImage(configuration); err != nil {
			return err
		}
		log.Default().Println("Preparing docker image transfer...")
		outputFile, err = builder.SaveImageToFile(configuration)
		if err != nil {
			return err
		}
	}

	composeFile, err := os.Open("compose.yml")
	if err != nil {
		return err
	}

	log.Default().Println("Deploying docker image to remote server...")
	if err := client.DeployImage(
		configuration.Name,
		outputFile,
		composeFile); err != nil {
		return err
	}
	return nil
}
