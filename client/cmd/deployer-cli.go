package main

import (
	"deployer/builder"
	"deployer/client"
	"deployer/client/config"
	"deployer/client/version"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var filePath string
	var configuration *config.Configuration
	var err error
	var revision *int32
	var newRevision *bool
	var prune *bool
	var deleteFiles *bool
	rootCmd := &cobra.Command{
		Use:     "deployer-client",
		Version: version.Version,
		Short:   "deployer client",
	}

	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "configuration file path")

	revision = rootCmd.PersistentFlags().Int32("revision", -1, "Set revision to use")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmd.Use != "config" {
			configuration, err = config.ReadConfiguration(filePath)
			if err != nil {
				log.Fatalf("Error reading configuration: %v", err)
			}
			if configuration.EnableRevisions && *revision == -1 {
				rev, err := readCurrentRevision()
				if err != nil {
					log.Fatalf("Error reading current revision: %v", err)
				}
				revision = &rev
			}
		}
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Generate a sample configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			err := config.WriteSampleConfiguration()
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
			err = builder.BuildImage(configuration, *revision)
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
			file, err := builder.SaveImageToFile(configuration, *revision)
			if err != nil {
				log.Fatalf("Error saving image to file: %v", err)
			} else {
				log.Printf("Docker image saved to file: %s", file)
			}
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			log.Default().Println("Starting remote container...")
			if err := client.StartContainer(configuration.Name, *revision); err != nil {
				log.Fatalf("Error starting container: %v", err)
			} else {
				log.Println("Container started successfully")
			}

		},
	})

	stopCommand := &cobra.Command{
		Use:   "stop",
		Short: "Stop the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			//TODO deleteFiles flag
			Connect(configuration)
			log.Default().Println("Stopping remote container...")
			if err := client.StopContainer(configuration.Name, *revision, *deleteFiles); err != nil {
				log.Fatalf("Error stopping container: %v", err)
			} else {
				log.Println("Container stopped successfully")
			}

		},
	}
	deleteFiles = stopCommand.Flags().BoolP("delete-files", "d", false, "Delete container config after stopping")
	rootCmd.AddCommand(stopCommand)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			log.Default().Println("Restarting remote container...")
			if err := client.RestartContainer(configuration.Name, *revision); err != nil {
				log.Fatalf("Error restarting container: %v", err)
			} else {
				log.Println("Container restarting successfully")
			}

		},
	})

	deployCmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy and starts the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			var rev int32
			rev = -1
			if configuration.EnableRevisions {
				rev = *revision
			}
			if *newRevision {
				if !configuration.EnableRevisions {
					log.Fatalf("Cannot create new revision when revisions are disabled in configuration, please set enable_revisions: true in config file")
				}
				CheckComposeFileForServiceNameCoherence(configuration)
				rev, err = readCurrentRevision()
				rev++
				if err != nil {
					log.Fatalf("Error reading current revision: %v", err)
				}
			}
			if err := DeployImage(configuration, rev, *prune); err != nil {
				log.Fatalf("Error deploying container: %v", err)
			} else {
				log.Println("Container deployed successfully")
			}
			if *newRevision {
				err = writeRevisionToFile(rev)
				if err != nil {
					log.Fatalf("Error writing revision '%d' to file: %v", rev, err)
				}
			}
		},
	}
	newRevision = deployCmd.Flags().BoolP("new-revision", "n", false, "Create a new revision for this deployment")
	prune = deployCmd.Flags().BoolP("prune", "p", false, "run docker image prune after deployment")
	rootCmd.AddCommand(deployCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "logs",
		Short: "Prints the logs of the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			channel, err := client.Logs(configuration.Name, *revision)
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

	rootCmd.AddCommand(&cobra.Command{
		Use:   "revisions",
		Short: "List the revisions running on the remote container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			revisions, err := client.Revisions(configuration.Name)
			if err != nil {
				log.Fatalf("Error getting revisions for container: %v", err)
			}
			for _, revision := range revisions {
				log.Println(" - ", revision)
			}
		},
	})
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func Connect(configuration *config.Configuration) {
	err := client.Connect(*configuration)
	if err != nil {
		log.Fatalf("Error connecting to remote server: %v", err)
	}
}

func DeployImage(configuration *config.Configuration, revision int32, prune bool) error {

	if err := builder.BuildImage(configuration, revision); err != nil {
		return err
	}
	log.Default().Println("Preparing docker image transfer...")
	outputFile, err := builder.SaveImageToFile(configuration, revision)
	if err != nil {
		return err
	}

	composeFile, err := os.Open(configuration.ComposePath)
	if err != nil {
		return err
	}

	log.Default().Println("Deploying docker image to remote server...")
	if err := client.DeployImage(
		configuration.Name,
		outputFile,
		composeFile,
		revision,
		prune); err != nil {
		return err
	}
	return nil
}

func readCurrentRevision() (int32, error) {
	rev, err := os.ReadFile("REVISION")
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return -1, err
	}
	var revision int32
	_, err = fmt.Sscanf(string(rev), "%d", &revision)
	if err != nil {
		return -1, err
	}
	return revision, nil
}

func writeRevisionToFile(revision int32) error {
	return os.WriteFile("REVISION", []byte(fmt.Sprint(revision)), 0644)
}
