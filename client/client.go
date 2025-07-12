package client

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"deployer/client/config"
	"deployer/protocol"
	"encoding/gob"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var sshConn *ssh.Client
var dataChannel ssh.Channel
var encoder *gob.Encoder
var decoder *gob.Decoder

func Connect(configuration config.Configuration) error {
	privateKey, err := loadPrivateKey(configuration)
	if err != nil {
		return err
	}

	sshConfig := &ssh.ClientConfig{
		User: "deployer",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: createHostKeyCallback(configuration),
	}

	sshConn, err = ssh.Dial("tcp", net.JoinHostPort(configuration.Host, strconv.Itoa(configuration.Port)), sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}

	// Open a session channel for data communication
	dataChannel, _, err = sshConn.OpenChannel("session", nil)
	if err != nil {
		sshConn.Close()
		return fmt.Errorf("failed to open SSH channel: %v", err)
	}

	encoder = gob.NewEncoder(dataChannel)
	decoder = gob.NewDecoder(dataChannel)
	return nil
}

func StartContainer(name string) error {
	return handleSimpleRequest(name, protocol.Start)
}

func StopContainer(name string) error {
	return handleSimpleRequest(name, protocol.Stop)
}

func RestartContainer(name string) error {
	return handleSimpleRequest(name, protocol.Restart)
}

func DeployImage(name string, tarFile *os.File, composeFile *os.File) error {
	return handleRequest(
		name,
		protocol.Deploy,
		tarFile,
		composeFile)
}

func Logs(name string) (<-chan string, error) {
	request := protocol.Request{
		Name:    name,
		Command: protocol.Logs,
	}
	if err := encoder.Encode(&request); err != nil {
		return nil, err
	}

	logChan := make(chan string)

	go func() {
		defer close(logChan)
		for {
			var response protocol.Response
			if err := decoder.Decode(&response); err != nil {
				log.Default().Println("Error decoding log response:", err)
				return
			}
			if response.Status == protocol.Ok {
				logChan <- response.Message
			} else {
				return
			}
		}
	}()

	return logChan, nil
}

func handleSimpleRequest(name string, req protocol.Command) error {
	return handleRequest(name, req, nil, nil)
}

func handleRequest(name string, req protocol.Command, tarFile *os.File, composeFile *os.File) error {
	var err error
	request := protocol.Request{
		Name:    name,
		Command: req,
	}

	if tarFile != nil {
		tarData, err := os.ReadFile(tarFile.Name())
		if err != nil {
			return err
		}
		request.TarImage = tarData
	}

	if composeFile != nil {
		composeData, err := os.ReadFile(composeFile.Name())
		if err != nil {
			return err
		}
		request.ComposeFile = composeData
	}

	if err = encoder.Encode(&request); err != nil {
		return err
	}
	var response protocol.Response
	if err = decoder.Decode(&response); err != nil {
		return err
	}
	if response.Status != protocol.Ok {
		return errors.New(response.Message)
	}
	return nil
}

func loadPrivateKey(configuration config.Configuration) (ssh.Signer, error) {

	var privateKeyPath string
	if configuration.PrivateKey != "" {
		privateKeyPath = configuration.PrivateKey
	} else {

		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %v", err)
		}

		// Try different key types in order of preference
		keyTypes := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}
		sshDir := filepath.Join(homeDir, ".ssh")

		for _, keyType := range keyTypes {
			keyPath := filepath.Join(sshDir, keyType)
			if _, err := os.Stat(keyPath); err == nil {
				privateKeyPath = keyPath
				break
			}
		}

		if privateKeyPath == "" {
			return nil, fmt.Errorf("no SSH private key found in %s (tried: %v)", sshDir, keyTypes)
		}

	}
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %v", privateKeyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key %s: %v", privateKeyPath, err)
	}

	return signer, nil
}

func createHostKeyCallback(configuration config.Configuration) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownHostsPath, err := getKnownHostsPath()
		if err != nil {
			return err
		}

		// Try to load existing known_hosts
		if _, err := os.Stat(knownHostsPath); err == nil {
			if _, exists := checkKnownHosts(knownHostsPath, hostname, key); exists {
				log.Printf("Host key verification successful for %s", hostname)
				return nil
			}
		}

		// Host not found in known_hosts, prompt user to accept
		fingerprint := getFingerprint(key)
		log.Printf("The authenticity of host '%s' can't be established", hostname)
		log.Printf("%s key fingerprint is %s", key.Type(), fingerprint)

		// For automated deployment, we can add the key automatically
		// In production, you might want to require manual verification
		if err := addToKnownHosts(knownHostsPath, hostname, key); err != nil {
			return fmt.Errorf("failed to add host key to known_hosts: %v", err)
		}

		log.Printf("Host key added to known_hosts for %s", hostname)
		return nil
	}
}

func getKnownHostsPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(homeDir, ".ssh", "known_hosts"), nil
}

func checkKnownHosts(knownHostsPath, hostname string, key ssh.PublicKey) (ssh.PublicKey, bool) {
	file, err := os.Open(knownHostsPath)
	if err != nil {
		return nil, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		hosts := strings.Split(parts[0], ",")
		for _, host := range hosts {
			if host == hostname {
				hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
				if err != nil {
					continue
				}
				// Compare the keys directly
				if bytes.Equal(hostKey.Marshal(), key.Marshal()) {
					return hostKey, true
				}
			}
		}
	}
	return nil, false
}

func addToKnownHosts(knownHostsPath, hostname string, key ssh.PublicKey) error {
	// Ensure .ssh directory exists
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	file, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	keyLine := string(ssh.MarshalAuthorizedKey(key))
	keyLine = fmt.Sprintf("%s %s", hostname, strings.TrimSpace(keyLine))
	_, err = file.WriteString(keyLine + "\n")
	return err
}

func getFingerprint(key ssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	fingerprint := ""
	for i, b := range hash {
		if i > 0 {
			fingerprint += ":"
		}
		fingerprint += fmt.Sprintf("%02x", b)
	}
	return fingerprint
}
