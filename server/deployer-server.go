package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"deployer/builder"
	"deployer/protocol"
	serverConfig "deployer/server/config"
	"deployer/server/version"
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

var config *serverConfig.ServerConfiguration
var TestingMode = false

func main() {
	versionFlag := flag.Bool("v", false, "Prints the version of the program")
	configFilePath := flag.String("config", "config.yaml", "Path to configuration file")
	sampleConfig := flag.Bool("sample-config", false, "Generate a sample configuration file")
	flag.Parse()
	var err error
	var listener net.Listener
	if *versionFlag {
		log.Printf("Deployer Server Version: %s", version.Version)
		return
	}
	if *sampleConfig {
		if err := serverConfig.CreateSampleConfig(*configFilePath); err != nil {
			log.Fatalf("Error generating sample configuration: %v", err)
		}
		return
	}

	if config, err = serverConfig.ReadServerConfiguration(*configFilePath); err != nil {
		log.Fatal(err)
	}

	err = os.Mkdir(config.WorkingDirectory, 0770)

	if err != nil && !os.IsExist(err) {
		log.Fatalf("Error creating directory %s: %v", config.WorkingDirectory, err)
	}

	hostKey, err := loadHostKey(config)
	if err != nil {
		log.Fatalf("Error loading host key: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return checkAuthorizedKey(key, conn)
		},
	}
	sshConfig.AddHostKey(hostKey)

	gob.Register(protocol.Request{})
	if listener, err = net.Listen("tcp", net.JoinHostPort(config.ListenAddress, strconv.Itoa(config.Port))); err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn, sshConfig)
	}
}

func handleConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic gestito in handleConnection: %v", r)
		}
	}()
	defer conn.Close()

	dataChannel, sshConn, err := handleSSHConnection(conn, sshConfig)
	if err != nil {
		log.Printf("Error handling SSH connection: %v", err)
		return
	}

	defer dataChannel.Close()
	defer sshConn.Close()

	handleRequest(dataChannel)
}

func handleRequest(dataChannel ssh.Channel) {
	decoder := gob.NewDecoder(dataChannel)
	encoder := gob.NewEncoder(dataChannel)
	var request protocol.Request
	if err := decoder.Decode(&request); err != nil {
		log.Printf("Error reading request, invalid format: %v", err)
		return
	}

	if request.Version != version.Version {
		log.Printf("Protocol version mismatch: client %s, server %s. Connection will be closed", request.Version, version.Version)
		_ = handleResponse("Protocol version mismatch: client: "+request.Version+", server: "+version.Version, protocol.Ko, encoder)
	}

	if request.Command == protocol.Stop {
		err := stopContainer(request)
		if err != nil {
			_ = handleResponse("Error stopping container: "+err.Error(), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		} else {
			_ = handleResponse("Container stopped successfully", protocol.Ok, encoder)
			return
		}
	} else if request.Command == protocol.Start {
		err := startContainer(request)
		if err != nil {
			_ = handleResponse("Error starting container: "+err.Error(), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		} else {
			_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)
			return
		}
	} else if request.Command == protocol.Deploy {
		composeFile := string(request.ComposeFile)
		tarFilePath := ""
		var err error
		if request.TarSize > 0 {
			fmt.Println("Receiving tar file of size", request.TarSize)
			tarFilePath, err = receiveStreamedTar(dataChannel, request.Name, request.TarSize)
			defer os.Remove(tarFilePath)
			if err != nil {
				log.Printf("Error saving files for deployment: %v", err)
				_ = handleResponse(fmt.Sprintf("Error receiving tar file: %v", err), protocol.Ko, encoder)
				return
			}
		} else {
			log.Printf("Error saving files for deployment: %v", err)
			_ = handleResponse(fmt.Sprintf("No tar file supplied"), protocol.Ko, encoder)
			return
		}

		if err := os.MkdirAll(getWorkingDirectory(request), 0770); err != nil && !os.IsExist(err) {
			log.Printf("Terminating deployment due to directory creation error: %v", err)
			_ = handleResponse(fmt.Sprintf("Error creating directory for container: %v", err), protocol.Ko, encoder)
			return
		}

		if tarFilePath != "" {
			if err = builder.ImportImageFromFile(tarFilePath); err != nil {
				log.Printf("Error importing image: %v", err)
				_ = handleResponse(fmt.Sprintf("Error importing tar file: %v", err), protocol.Ko, encoder)
				return
			}
		}

		if err = saveComposeFile(request, composeFile); err != nil {
			_ = handleResponse(fmt.Sprintf("Error saving compose file: %v", err), protocol.Ko, encoder)
			log.Printf("Error saving compose file for container %s: %v", request.Name, err)
			return
		}

		if err = stopContainer(request); err != nil {
			_ = handleResponse(fmt.Sprintf("Error stopping container: %v", err), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		}
		if err = startContainer(request); err != nil {
			_ = handleResponse(fmt.Sprintf("Error starting container: %v", err), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		}
		if request.Prune {
			cmd := exec.Command("docker", "image", "prune", "-f", "-a")
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("Error pruning images: %v. Output: %s", err, string(output))
			}
		}
		_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)
	} else if request.Command == protocol.Restart {
		if err := stopContainer(request); err != nil {
			_ = handleResponse(fmt.Sprintf("Error stopping container: %v", err), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		}
		if err := startContainer(request); err != nil {
			_ = handleResponse(fmt.Sprintf("Error starting container: %v", err), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		}
		_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)

	} else if request.Command == protocol.Logs {
		if request.Command == protocol.Logs {
			cmd := exec.Command("docker", "compose", "logs", "-f")
			cmd.Dir = config.WorkingDirectory + "/" + request.Name
			if request.Revision != "" {
				cmd.Dir = cmd.Dir + "/" + request.Revision
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				_ = handleResponse("Errore apertura pipe logs: "+err.Error(), protocol.Ko, encoder)
				return
			}
			if err := cmd.Start(); err != nil {
				_ = handleResponse("Errore avvio logs: "+err.Error(), protocol.Ko, encoder)
				return
			}
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				if err := handleResponse(scanner.Text(), protocol.Ok, encoder); err != nil {
					_ = cmd.Process.Kill()
					return
				}
			}
			_ = cmd.Wait()
			_ = handleResponse("Fine log", protocol.Ok, encoder)
			return
		}
	} else if request.Command == protocol.Revisions {
		revisions, err := getRunningRevisions(request.Name)
		if err != nil {
			_ = handleResponse(fmt.Sprintf("Error retrieving revisions: %v", err), protocol.Ko, encoder)
			log.Printf("Error retrieving revisions for container %s: %v", request.Name, err)
			return
		} else {
			message, err := json.Marshal(protocol.RevisionsDetails{
				Revisions: revisions,
			})
			if err != nil {
				_ = handleResponse(fmt.Sprintf("Error preparing revisions response: %v", err), protocol.Ko, encoder)
				log.Printf("Error preparing revisions response for container %s: %v", request.Name, err)
				return
			}
			handleResponse(string(message), protocol.Ok, encoder)
			return
		}
	} else {
		_ = handleResponse(fmt.Sprintf("Unknown command: %v", request.Command), protocol.Ko, encoder)
		log.Printf("Unknown request received: %v", request.String())
		return
	}
}

func getRunningRevisions(name string) ([]string, error) {
	cmd := exec.Command("docker", "ps", "--filter", "name=^"+name, "--format", "{{.ID}} {{.Names}}")
	cmd.Dir = config.WorkingDirectory + "/" + name
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.New("Error retrieving running containers: " + err.Error() + ". Output: " + string(output))
	}
	var revisions []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				revisions = append(revisions, parts[1])
			}
		}
	}
	return revisions, nil
}

func handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig) (ssh.Channel, *ssh.ServerConn, error) {
	sshConn, channels, requests, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("Errore handshake SSH: %v", err)
		return nil, nil, fmt.Errorf("SSH handshake failed: %v", err)
	}

	go ssh.DiscardRequests(requests)
	var dataChannel ssh.Channel
	var readSshChannel = make(chan ssh.Channel)

	go func() {
		var returnChannel ssh.Channel
		for newChannel := range channels {
			if newChannel.ChannelType() == "session" {
				channel, _, err := newChannel.Accept()
				if err != nil {
					log.Printf("Error accepting channel: %v", err)
					break
				}
				returnChannel = channel
				break
			} else {
				newChannel.Reject(ssh.UnknownChannelType, "channel type not supported")
			}
		}
		readSshChannel <- returnChannel
	}()

	select {
	case c := <-readSshChannel:
		dataChannel = c
	case <-time.After(10 * time.Second):
		dataChannel = nil
	}

	if dataChannel == nil {
		return nil, nil, fmt.Errorf("no session channel created")
	}

	return dataChannel, sshConn, nil
}

func saveComposeFile(request protocol.Request, fileContent string) error {
	var filePath = getWorkingDirectory(request) + "/docker-compose.yml"
	os.Remove(filePath)
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.New("Error opening file for writing: " + err.Error())
	}
	defer file.Close()

	var doc = make(map[string]interface{})

	if err := yaml.Unmarshal([]byte(fileContent), &doc); err != nil {
		return errors.New("Error parsing compose file content: " + err.Error())
	}

	if request.Revision != "" {
		if services, ok := doc["services"].(map[string]interface{}); ok {
			if svc, ok := services[request.Name].(map[string]interface{}); ok {
				if img, ok := svc["image"].(string); ok && img != "" {
					if !strings.Contains(img, ":") {
						svc["image"] = img + ":" + request.Revision
					}
				} else {
					return errors.New("Compose file must specify an image for service " + request.Name)
				}
				if img, ok := svc["container_name"].(string); ok && img != "" {
					svc["container_name"] = svc["container_name"].(string) + "_" + request.Revision
				}
			} else {
				return errors.New("Compose file does not contain service " + request.Name + ". This is required to use revisions.")
			}
		}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("Error serializing compose file: %v", err)
	}

	if _, err := file.Write(out); err != nil {
		return errors.New("Error writing to file: " + err.Error())
	}
	return nil
}

func receiveStreamedTar(dataChannel ssh.Channel, name string, tarSize int64) (string, error) {
	log.Printf("Starting to receive tar file of %d bytes", tarSize)
	tarFilePath := filepath.Join(config.WorkingDirectory, name+".tar")
	tarFile, err := os.Create(tarFilePath)
	defer func(tarFile *os.File) {
		err := tarFile.Close()
		if err != nil {
			log.Printf("Error closing tar file: %v", err)
		}
	}(tarFile)
	if err != nil {
		return "", fmt.Errorf("error creating tar file: %v", err)
	}
	timeoutHandler := &TimeoutHandler{}
	teeReader := io.TeeReader(dataChannel, timeoutHandler)
	doneChannel := make(chan interface{})
	log.Printf("Created tar file at %s, starting copy...", tarFilePath)
	reader, err := zlib.NewReader(teeReader)
	if err != nil {
		doneChannel <- fmt.Errorf("error creating zlib reader: %v", err)
	}
	timeoutChannel := timeoutHandler.StartMonitoring(5 * time.Second)
	defer func(reader io.ReadCloser) {
		err := reader.Close()
		if err != nil {
			log.Printf("Error closing zlib reader: %v", err)
		}
	}(reader)
	go func() {
		written, err := io.Copy(tarFile, reader)
		log.Printf("Copied %d bytes out of %d expected", written, tarSize)
		doneChannel <- struct{}{}
		if err != nil {
			doneChannel <- fmt.Errorf("error writing tar file: %v", err)
		}
	}()

	for {
		select {
		case <-timeoutChannel:
			log.Printf("Timeout detected while receiving tar file")
			return tarFile.Name(), nil
		case result := <-doneChannel:
			switch v := result.(type) {
			case error:
				return "", v
			case struct{}:
				return tarFile.Name(), nil
			}
		}
	}

}

func stopContainer(request protocol.Request) error {
	cmd := exec.Command("docker", "compose", "down")
	cmd.Dir = getWorkingDirectory(request)
	output, err := cmd.CombinedOutput()
	if err != nil && !TestingMode {
		return errors.New("Error stopping container: " + err.Error() + ". Output: " + string(output))
	}
	if request.DeleteFiles {
		return os.RemoveAll(getWorkingDirectory(request))
	}
	return nil
}

func startContainer(request protocol.Request) error {
	composeFile := string(request.ComposeFile)
	err := saveComposeFile(request, composeFile)
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "compose", "up", "-d")
	cmd.Dir = getWorkingDirectory(request)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("Error starting container: " + err.Error() + ". Output: " + string(output))
	}
	return nil
}

func handleResponse(message string, status protocol.Status, encoder *gob.Encoder) error {
	return encoder.Encode(protocol.Response{
		Status:  status,
		Message: message,
	})
}

func checkAuthorizedKey(clientKey ssh.PublicKey, conn ssh.ConnMetadata) (*ssh.Permissions, error) {
	authorizedKeysPath := filepath.Join(config.WorkingDirectory, "authorized_keys")

	if err := checkFilePermissions(authorizedKeysPath); err != nil {
		log.Printf("Security check failed for authorized_keys: %v", err)
		return nil, fmt.Errorf("access denied")
	}

	authorizedKeysBytes, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Authorized keys file not found at %s", authorizedKeysPath)
			return nil, fmt.Errorf("access denied")
		}
		log.Printf("Error reading authorized keys file: %v", err)
		return nil, fmt.Errorf("access denied")
	}

	for _, line := range strings.Split(string(authorizedKeysBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}

		if bytes.Equal(clientKey.Marshal(), authorizedKey.Marshal()) {
			log.Printf("SSH authentication successful for key type %s from host %s", clientKey.Type(), conn.RemoteAddr().String())
			return &ssh.Permissions{}, nil
		}
	}

	log.Printf("SSH authentication failed: key not found in authorized_keys from host %s", conn.RemoteAddr().String())
	return nil, fmt.Errorf("access denied")
}

func checkFilePermissions(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	mode := fileInfo.Mode()

	if mode&0077 != 0 {
		return fmt.Errorf("authorized_keys file has insecure permissions %o, should be 600", mode.Perm())
	}

	return nil
}

func loadHostKey(configuration *serverConfig.ServerConfiguration) (ssh.Signer, error) {
	var keyPath string

	if configuration.HostKeyPath != "" {
		keyPath = configuration.HostKeyPath
	} else {
		keyPath = "/opt/deployer/host_rsa_key"
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("host key not found at %s. Please specify a valid host key path in configuration or ensure the system host key exists", keyPath)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file %s: %v", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key %s: %v", keyPath, err)
	}

	log.Printf("Loaded host key from %s", keyPath)
	return signer, nil
}

func getWorkingDirectory(request protocol.Request) string {
	dir := config.WorkingDirectory + "/" + request.Name
	if request.Revision != "" {
		dir += "/" + request.Revision
	}
	return dir
}
