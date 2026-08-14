package main

import (
	"bufio"
	"deployer/builder"
	"deployer/client"
	"deployer/client/config"
	"deployer/client/version"
	"deployer/protocol"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func main() {
	var filePath string
	var configuration *config.Configuration
	var err error
	var revision *int32
	var port *int32 //used in Ports command
	var newRevision *bool
	var json *bool
	var lbStatusJson *bool
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
				if configuration.RevisionsRemovePrevious {
					removePreviousRevisions(configuration, rev)
				}
			}
		},
	}

	pushCmd := &cobra.Command{
		Use:   "push",
		Short: "Push image and compose file to remote server without (re)starting the container",
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
			if err := PushImage(configuration, rev, *prune); err != nil {
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

	prune = pushCmd.Flags().BoolP("prune", "p", false, "run docker image prune after deployment")
	rootCmd.AddCommand(pushCmd)

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

	portsCommand := &cobra.Command{
		Use:   "ports",
		Short: "List ports (and mappings) for a container",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			ports, err := client.Ports(configuration.Name, revision, port)
			if err != nil {
				log.Fatal(err)
			}
			displayPorts(ports, json)
		},
	}
	port = portsCommand.Flags().Int32P("port", "p", -1, "Specify the port to display info on")
	json = portsCommand.Flags().BoolP("json", "j", false, "Format output as json")
	rootCmd.AddCommand(portsCommand)

	lbStatusCommand := &cobra.Command{
		Use:   "lb-status",
		Short: "Show the Continuity load balancer pool the project is published on",
		Run: func(cmd *cobra.Command, args []string) {
			Connect(configuration)
			status, err := client.LbStatus(configuration.Name)
			if err != nil {
				log.Fatal(err)
			}
			displayLbStatus(status, lbStatusJson)
		},
	}
	lbStatusJson = lbStatusCommand.Flags().BoolP("json", "j", false, "Format output as json")
	rootCmd.AddCommand(lbStatusCommand)

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
	composeFile, err := os.Open(configuration.ComposePath)
	if err != nil {
		return err
	}
	defer func(composeFile *os.File) {
		_ = composeFile.Close()
	}(composeFile)
	outputFile, err := buildAndExportImage(configuration, revision)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			log.Default().Println("Warning: could not delete temporary file:", name)
		}
	}(outputFile)
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

func PushImage(configuration *config.Configuration, revision int32, prune bool) error {
	composeFile, err := os.Open(configuration.ComposePath)
	if err != nil {
		return err
	}
	defer func(composeFile *os.File) {
		_ = composeFile.Close()
	}(composeFile)
	outputFile, err := buildAndExportImage(configuration, revision)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			log.Default().Println("Warning: could not delete temporary file:", name)
		}
	}(outputFile)
	if err != nil {
		return err
	}
	log.Default().Println("Deploying docker image to remote server...")
	if err := client.PushImage(
		configuration.Name,
		outputFile,
		composeFile,
		revision,
		prune); err != nil {
		return err
	}
	return nil
}

func buildAndExportImage(configuration *config.Configuration, revision int32) (string, error) {
	if err := builder.BuildImage(configuration, revision); err != nil {
		return "", err
	}
	log.Default().Println("Preparing docker image transfer...")
	outputFile, err := builder.SaveImageToFile(configuration, revision)
	if err != nil {
		return "", err
	}

	return outputFile, nil
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

// parseRevisionNumber extracts the numeric revision from a running container
// name. The server names revision containers as "<container_name>-<revision>",
// so the revision is the token after the last '-'. Only the trailing numeric
// token is trusted, which keeps this independent of the container_name prefix
// (it may differ from the configured project name). Returns false when the
// trailing token is not a number.
func parseRevisionNumber(name string) (int32, bool) {
	idx := strings.LastIndex(name, "-")
	if idx < 0 || idx == len(name)-1 {
		return 0, false
	}
	n, err := strconv.ParseInt(name[idx+1:], 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}

// removePreviousRevisions implements the revisions_remove_previous behaviour:
// after a successful --new-revision deploy, stop the revision(s) that were
// running before. It is best-effort — the deploy already succeeded, so any
// failure here is only a warning and never aborts the command.
func removePreviousRevisions(configuration *config.Configuration, newRev int32) {
	Connect(configuration)
	names, err := client.Revisions(configuration.Name)
	if err != nil {
		log.Printf("Warning: could not list revisions to remove previous ones: %v", err)
		return
	}

	seen := make(map[int32]bool)
	var candidates []int32
	for _, name := range names {
		n, ok := parseRevisionNumber(name)
		if !ok || n == newRev || seen[n] {
			continue
		}
		seen[n] = true
		candidates = append(candidates, n)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] < candidates[j] })

	toStop := selectRevisionsToStop(candidates, os.Stdin)
	for _, n := range toStop {
		log.Printf("Stopping previous revision %d...", n)
		Connect(configuration)
		if err := client.StopContainer(configuration.Name, n, false); err != nil {
			log.Printf("Warning: could not stop previous revision %d: %v", n, err)
		}
	}
}

// selectRevisionsToStop decides which of the candidate previous revisions to
// stop. Zero candidates -> none; exactly one -> stop it implicitly; two or more
// -> prompt the user when interactive, otherwise warn and skip. The reader is
// injectable for testing.
func selectRevisionsToStop(candidates []int32, r *os.File) []int32 {
	switch len(candidates) {
	case 0:
		return nil
	case 1:
		return candidates
	}

	info, _ := r.Stat()
	interactive := info != nil && (info.Mode()&os.ModeCharDevice) != 0
	if !interactive {
		log.Printf("Warning: multiple previous revisions are running (%v) but the terminal is not interactive; skipping removal. Stop them manually with 'stop --revision N'.", candidates)
		return nil
	}
	return promptSelectRevisions(candidates, r)
}

// promptSelectRevisions asks the user which of the (2+) candidate revisions to
// stop. Input is a list of 1-based indices separated by commas/spaces, the word
// 'all', or empty to skip. Invalid input is re-prompted up to 3 times, then
// treated as skip. The reader is injectable for testing.
func promptSelectRevisions(candidates []int32, r io.Reader) []int32 {
	reader := bufio.NewReader(r)
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Println("Multiple previous revisions are running. Which do you want to stop?")
		for i, n := range candidates {
			fmt.Printf("  %d) revision %d\n", i+1, n)
		}
		fmt.Print("Enter numbers separated by comma/space, 'all', or leave empty to skip: ")

		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			log.Printf("Warning: could not read selection: %v; skipping removal.", err)
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return nil
		}
		if strings.EqualFold(line, "all") {
			return candidates
		}

		fields := strings.FieldsFunc(line, func(c rune) bool { return c == ',' || c == ' ' })
		selected := make(map[int32]bool)
		var result []int32
		valid := true
		for _, f := range fields {
			idx, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || idx < 1 || idx > len(candidates) {
				valid = false
				break
			}
			n := candidates[idx-1]
			if !selected[n] {
				selected[n] = true
				result = append(result, n)
			}
		}
		if valid && len(result) > 0 {
			return result
		}
		fmt.Println("Invalid selection, please try again.")
	}
	log.Printf("Warning: no valid selection after 3 attempts; skipping removal.")
	return nil
}

func displayPorts(ports []protocol.Port, jsonFormat *bool) {
	if *jsonFormat {
		j, _ := json.Marshal(ports)
		fmt.Println(string(j))
	} else {
		for _, port := range ports {
			fmt.Printf("Address: %s, Container port: %s, Host port: %s, Protocol: %s\n", port.Address, port.LocalPort, port.BindPort, port.Protocol)
		}
	}
}

func displayLbStatus(status protocol.LbStatusResponse, jsonFormat *bool) {
	if *jsonFormat {
		j, _ := json.Marshal(status)
		fmt.Println(string(j))
		return
	}
	fmt.Printf("Pool: %s\n", status.Hostname)
	if len(status.Backends) == 0 {
		fmt.Println("No backends registered")
		return
	}
	for _, backend := range status.Backends {
		kind := "unconditional"
		if backend.Conditional {
			kind = "conditional"
		}
		fmt.Printf("- %s [%s] health-check: %s (%s)\n", backend.Address, backend.Status, backend.HealthCheckPath, kind)
	}
}
