package main

import (
	"bufio"
	"bytes"
	"deployer/builder"
	"deployer/protocol"
	serverConfig "deployer/server/config"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var config *serverConfig.ServerConfiguration

func main() {
	configFilePath := flag.String("config", "config.yaml", "Path to configuration file")
	sampleConfig := flag.Bool("sample-config", false, "Generate a sample configuration file")
	flag.Parse()
	var err error
	var listener net.Listener

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

	decoder := gob.NewDecoder(dataChannel)
	encoder := gob.NewEncoder(dataChannel)
	var request protocol.Request
	if err := decoder.Decode(&request); err != nil {
		log.Printf("Error reading request, invalid format: %v", err)
		return
	}

	if request.Command == protocol.Stop {
		err := stopContainer(request.Name)
		if err != nil {
			_ = handleResponse("Error stopping container: "+err.Error(), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		} else {
			_ = handleResponse("Container stopped successfully", protocol.Ok, encoder)
			return
		}
	} else if request.Command == protocol.Start {
		err := startContainer(request.Name, string(request.ComposeFile))
		if err != nil {
			_ = handleResponse("Error starting container: "+err.Error(), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		} else {
			_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)
			return
		}
	} else if request.Command == protocol.Deploy {
		tarFile, composeFile, err := receiveTarAndComposeFile(request)
		if err != nil {
			_ = handleResponse(fmt.Sprintf("Error receiving tar file: %v", err), protocol.Ko, encoder)
			log.Printf("Error saving files for deployment: %v", err)
			return
		}
		if tarFile != nil {
			defer os.Remove(tarFile.Name())
		}

		if err := os.Mkdir(config.WorkingDirectory+"/"+request.Name, 0770); err != nil && !os.IsExist(err) {
			_ = handleResponse(fmt.Sprintf("Error creating directory for container: %v", err), protocol.Ko, encoder)
			log.Printf("Terminating deployment due to directory creation error: %v", err)
			return
		}

		if tarFile != nil {
			if err = builder.ImportImageFromFile(tarFile.Name()); err != nil {
				_ = handleResponse(fmt.Sprintf("Error importing tar file: %v", err), protocol.Ko, encoder)
				return
			}
		}

		if err = saveComposeFile(request.Name, composeFile); err != nil {
			_ = handleResponse(fmt.Sprintf("Error saving compose file: %v", err), protocol.Ko, encoder)
			log.Printf("Error saving compose file for container %s: %v", request.Name, err)
			return
		}

		if err = stopContainer(request.Name); err != nil {
			_ = handleResponse(fmt.Sprintf("Error stopping container: %v", err), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		}
		if err = startContainer(request.Name, string(request.ComposeFile)); err != nil {
			_ = handleResponse(fmt.Sprintf("Error starting container: %v", err), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		}
		_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)
	} else if request.Command == protocol.Restart {
		if err := stopContainer(request.Name); err != nil {
			_ = handleResponse(fmt.Sprintf("Error stopping container: %v", err), protocol.Ko, encoder)
			log.Printf("Error stopping container %s: %v", request.Name, err)
			return
		}
		if err := startContainer(request.Name, string(request.ComposeFile)); err != nil {
			_ = handleResponse(fmt.Sprintf("Error starting container: %v", err), protocol.Ko, encoder)
			log.Printf("Error starting container %s: %v", request.Name, err)
			return
		}
		_ = handleResponse(fmt.Sprintf("Container started successfully"), protocol.Ok, encoder)

	} else if request.Command == protocol.Logs {
		if request.Command == protocol.Logs {
			cmd := exec.Command("docker", "compose", "logs", "-f")
			cmd.Dir = config.WorkingDirectory + "/" + request.Name
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
	} else {
		_ = handleResponse(fmt.Sprintf("Unknown command: %v", request.Command), protocol.Ko, encoder)
		log.Printf("Unknown request received: %v", request.String())
		return
	}
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

func saveComposeFile(name string, fileContent string) error {
	var filePath = config.WorkingDirectory + "/" + name + "/docker-compose.yml"
	os.Remove(filePath)
	file, err := os.OpenFile(config.WorkingDirectory+"/"+name+"/docker-compose.yml", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return errors.New("Error opening file for writing: " + err.Error())
	}
	defer file.Close()
	if _, err := file.WriteString(fileContent); err != nil {
		return errors.New("Error writing to file: " + err.Error())
	}
	return nil
}

func receiveTarAndComposeFile(req protocol.Request) (*os.File, string, error) {
	var tarFile *os.File
	if req.TarImage != nil {
		var err error
		tarFile, err = os.Create(config.WorkingDirectory + "/" + req.Name + ".tar")
		if err != nil {
			return nil, "", errors.New("Error creating temporary tar file: " + err.Error())
		}
		defer tarFile.Close()

		if _, err := tarFile.Write(req.TarImage); err != nil {
			return nil, "", errors.New("Error writing to temporary tar file: " + err.Error())
		}
	}

	composeFile := string(req.ComposeFile)
	return tarFile, composeFile, nil
}

func stopContainer(name string) error {
	cmd := exec.Command("docker", "compose", "down")
	cmd.Dir = config.WorkingDirectory + "/" + name
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("Error stopping container: " + err.Error() + ". Output: " + string(output))
	}
	return nil
}

func startContainer(name string, composeFile string) error {
	if composeFile != "" {
		composeFilePath := config.WorkingDirectory + "/" + name + "/docker-compose.yml"
		file, err := os.OpenFile(composeFilePath, os.O_WRONLY|os.O_CREATE, 0600)
		defer file.Close()
		if err != nil {
			return errors.New("Error opening file " + composeFilePath + ": " + err.Error())
		}
		_, err = file.WriteString(composeFile)
		if err != nil {
			return errors.New("Error writing to file " + composeFilePath + ": " + err.Error())
		}
	}
	cmd := exec.Command("docker", "compose", "up", "-d")
	cmd.Dir = config.WorkingDirectory + "/" + name
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
