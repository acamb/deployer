package config

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	Host                    string      `yaml:"host"`
	Port                    int         `yaml:"port"`
	Name                    string      `yaml:"name"`
	ImageName               string      `yaml:"image_name"`
	PrivateKey              string      `yaml:"private_key"`
	ComposePath             string      `yaml:"compose_file_path"`
	BuildMethod             BuildMethod `yaml:"build_method"`
	EnableRevisions         bool        `yaml:"enable_revisions"`
	RevisionsRemovePrevious bool        `yaml:"revisions_remove_previous"`

	EkvsEnable     bool   `yaml:"ekvs_enable"`
	EkvsServer     string `yaml:"ekvs_server"`
	EkvsProject    string `yaml:"ekvs_project"`
	EkvsPrivateKey string `yaml:"ekvs_private_key"`

	// ContinuityPrivateKey is fully optional and has no fallback (unlike
	// EkvsPrivateKey): when left empty, it means the auth_key referenced
	// inside ContinuityConfig already points to a key present on the
	// server, placed there manually by an administrator.
	// ContinuityAdvertiseBase optionally overrides the deployer server's
	// own continuity_advertise_base for this project: the base URL, scheme
	// included and without port, under which the container is reachable by
	// Continuity. The published Docker port is appended to it.
	ContinuityEnable          bool   `yaml:"continuity_enable"`
	ContinuityConfig          string `yaml:"continuity_config"`
	ContinuityPrivateKey      string `yaml:"continuity_private_key"`
	ContinuityPool            string `yaml:"continuity_pool"`
	ContinuityHealthCheckPath string `yaml:"continuity_health_check_path"`
	ContinuityInternalPort    string `yaml:"continuity_internal_port"`
	ContinuityRemovePrevious  bool   `yaml:"continuity_remove_previous"`
	ContinuityAdvertiseBase   string `yaml:"continuity_advertise_base"`
}

// continuityFileConfig mirrors the subset of the native Continuity CLI
// configuration file that deployer needs to validate before forwarding its
// contents to the server. Continuity itself does no `~` expansion and builds
// its endpoint by plain concatenation, so a missing scheme or a non-absolute
// auth_key can only be detected here.
type continuityFileConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	DefaultPool string `yaml:"default_pool"`
	AuthKey     string `yaml:"auth_key"`
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

	if config.PrivateKey != "" {
		expanded, err := expandHome(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand private_key path %q: %v", config.PrivateKey, err)
		}
		config.PrivateKey = expanded
	}
	if config.EkvsPrivateKey != "" {
		expanded, err := expandHome(config.EkvsPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand ekvs_private_key path %q: %v", config.EkvsPrivateKey, err)
		}
		config.EkvsPrivateKey = expanded
	}
	if config.ContinuityConfig != "" {
		expanded, err := expandHome(config.ContinuityConfig)
		if err != nil {
			return nil, fmt.Errorf("cannot expand continuity_config path %q: %v", config.ContinuityConfig, err)
		}
		config.ContinuityConfig = expanded
	}
	if config.ContinuityPrivateKey != "" {
		expanded, err := expandHome(config.ContinuityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("cannot expand continuity_private_key path %q: %v", config.ContinuityPrivateKey, err)
		}
		config.ContinuityPrivateKey = expanded
	}

	if config.ImageName == "" {
		config.ImageName = config.Name
	}

	if !strings.Contains(config.ImageName, ":") && !config.EnableRevisions {
		config.ImageName += ":latest"
	} else if strings.Contains(config.ImageName, ":") && config.EnableRevisions {
		log.Fatal("Error: enable_revisions cannot be true when image_name contains a tag. Please remove the tag from image_name.")
	}

	if err := validateEkvs(config); err != nil {
		return nil, err
	}

	if err := validateContinuity(config); err != nil {
		return nil, err
	}

	return config, nil
}

func validateEkvs(config *Configuration) error {
	if !config.EkvsEnable {
		return nil
	}
	if strings.TrimSpace(config.EkvsServer) == "" {
		return fmt.Errorf("ekvs_enable is true but ekvs_server is not set")
	}
	if strings.TrimSpace(config.EkvsProject) == "" {
		return fmt.Errorf("ekvs_enable is true but ekvs_project is not set")
	}
	if strings.TrimSpace(config.EkvsPrivateKey) == "" {
		if strings.TrimSpace(config.PrivateKey) != "" {
			log.Printf("ekvs_private_key not set: using private_key %q as EKVS key. Set 'ekvs_private_key' in the config file to use a dedicated key.", config.PrivateKey)
			config.EkvsPrivateKey = config.PrivateKey
		} else {
			discovered, err := FindDefaultSSHKey()
			if err != nil {
				return fmt.Errorf("ekvs_enable is true but no private key is available: %v", err)
			}
			log.Printf("ekvs_private_key and private_key not set: using auto-discovered SSH key %q as EKVS key. Set 'ekvs_private_key' in the config file to use a dedicated key.", discovered)
			config.EkvsPrivateKey = discovered
		}
	}
	return checkReadableFile(config.EkvsPrivateKey, "ekvs_private_key")
}

// validateContinuity validates the Continuity integration fields. Unlike
// validateEkvs, ContinuityPrivateKey has no fallback: an empty value is a
// deliberate choice meaning the auth_key referenced inside ContinuityConfig
// already points to a key present on the server (Path B), so no local file
// is required or checked here in that case.
func validateContinuity(config *Configuration) error {
	if !config.ContinuityEnable {
		return nil
	}
	if strings.TrimSpace(config.ContinuityConfig) == "" {
		return fmt.Errorf("continuity_enable is true but continuity_config is not set")
	}
	if err := checkReadableFile(config.ContinuityConfig, "continuity_config"); err != nil {
		return err
	}

	// The server resolves the published Docker port starting from this
	// internal port: without it there is nothing to look up and the backend
	// registration would silently find no port at all.
	if strings.TrimSpace(config.ContinuityInternalPort) == "" {
		return fmt.Errorf("continuity_enable is true but continuity_internal_port is not set")
	}
	port, err := strconv.Atoi(strings.TrimSpace(config.ContinuityInternalPort))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("continuity_internal_port %q is not a valid port number", config.ContinuityInternalPort)
	}

	// An empty health check path is fine: the continuity CLI already
	// defaults to /health.
	if hc := strings.TrimSpace(config.ContinuityHealthCheckPath); hc != "" && !strings.HasPrefix(hc, "/") {
		return fmt.Errorf("continuity_health_check_path %q must start with '/'", config.ContinuityHealthCheckPath)
	}

	if err := validateAdvertiseBase(config); err != nil {
		return err
	}

	if err := validateContinuityFile(config); err != nil {
		return err
	}

	if strings.TrimSpace(config.ContinuityPrivateKey) == "" {
		return nil
	}
	return checkReadableFile(config.ContinuityPrivateKey, "continuity_private_key")
}

// validateAdvertiseBase normalizes and validates ContinuityAdvertiseBase: it
// must be a bare origin, because the server appends ":<published-port>" to it
// to build the backend address. A trailing slash is trimmed rather than
// rejected.
func validateAdvertiseBase(config *Configuration) error {
	base := strings.TrimRight(strings.TrimSpace(config.ContinuityAdvertiseBase), "/")
	config.ContinuityAdvertiseBase = base
	if base == "" {
		return nil
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("continuity_advertise_base %q is not a valid URL: %v", base, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("continuity_advertise_base %q must start with http:// or https://", base)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("continuity_advertise_base %q does not contain a host", base)
	}
	if parsed.Port() != "" {
		return fmt.Errorf("continuity_advertise_base %q must not contain a port: the published container port is appended by the server", base)
	}
	if parsed.Path != "" {
		return fmt.Errorf("continuity_advertise_base %q must not contain a path", base)
	}
	return nil
}

// validateContinuityFile inspects the native Continuity configuration file
// whose contents are forwarded to the server, checking the mistakes Continuity
// itself cannot recover from and that would otherwise only surface on the
// server: a 'host' without scheme (continuity builds its endpoint by plain
// concatenation), a pool that cannot be resolved, and — in Path B only — an
// 'auth_key' that is not an absolute path (continuity does no `~` expansion
// and resolves it on the server's filesystem).
func validateContinuityFile(config *Configuration) error {
	data, err := os.ReadFile(config.ContinuityConfig)
	if err != nil {
		return fmt.Errorf("cannot read continuity_config file %q: %v", config.ContinuityConfig, err)
	}
	var file continuityFileConfig
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("cannot parse continuity_config file %q: %v", config.ContinuityConfig, err)
	}

	host := strings.TrimSpace(file.Host)
	if host == "" {
		return fmt.Errorf("continuity_config %q does not set 'host'", config.ContinuityConfig)
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		return fmt.Errorf("'host' %q in continuity_config %q must include the scheme (e.g. http://%s): continuity builds its endpoint by concatenation", host, config.ContinuityConfig, host)
	}

	if strings.TrimSpace(config.ContinuityPool) == "" && strings.TrimSpace(file.DefaultPool) == "" {
		return fmt.Errorf("continuity_pool is not set and continuity_config %q has no 'default_pool': continuity would reject every command", config.ContinuityConfig)
	}

	// Path A: the server rewrites auth_key to point at the key it stores, so
	// whatever the file currently holds is irrelevant.
	if strings.TrimSpace(config.ContinuityPrivateKey) != "" {
		return nil
	}
	authKey := strings.TrimSpace(file.AuthKey)
	if authKey == "" {
		return fmt.Errorf("continuity_private_key is not set and continuity_config %q has no 'auth_key': no key would be available to authenticate against continuity", config.ContinuityConfig)
	}
	if strings.HasPrefix(authKey, "~") {
		return fmt.Errorf("'auth_key' %q in continuity_config %q must be an absolute path: continuity does not expand '~'", authKey, config.ContinuityConfig)
	}
	if !isServerAbsPath(authKey) {
		return fmt.Errorf("'auth_key' %q in continuity_config %q must be an absolute path on the deployer server", authKey, config.ContinuityConfig)
	}
	return nil
}

// isServerAbsPath reports whether path is absolute from the point of view of
// the deployer *server*, which is normally Linux even when the client runs on
// Windows: filepath.IsAbs alone would reject "/opt/deployer/key" on a Windows
// client.
func isServerAbsPath(path string) bool {
	return strings.HasPrefix(path, "/") || filepath.IsAbs(path)
}

// checkReadableFile verifies that path exists, is not a directory, and can
// be opened for reading. fieldName is used to produce a descriptive error.
func checkReadableFile(path string, fieldName string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access %s file %q: %v", fieldName, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s %q is a directory, expected a file", fieldName, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read %s file %q: %v", fieldName, path, err)
	}
	_ = f.Close()
	return nil
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

var DefaultSSHKeyTypes = []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}

func FindDefaultSSHKey() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	for _, keyType := range DefaultSSHKeyTypes {
		keyPath := filepath.Join(sshDir, keyType)
		if _, err := os.Stat(keyPath); err == nil {
			return keyPath, nil
		}
	}
	return "", fmt.Errorf("no SSH private key found in %s (tried: %v)", sshDir, DefaultSSHKeyTypes)
}

func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return home + path[1:], nil
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
#enable_revisions will manage different revisions for the same project, useful for zero-downtime deployments and rollbacks.
#enable_revisions: true
#revisions_remove_previous will, on a successful --new-revision deploy, stop the revision(s)
#that were running before. If more than one is running you are asked which to stop; if exactly
#one, it is stopped automatically. The stopped revision's files are kept for rollback.
#revisions_remove_previous: true
##EKVS integration (optional): inject secrets from an EKVS server into the
##container environment. When ekvs_enable is true, ekvs_server and
##ekvs_project are required. ekvs_private_key is optional: if omitted, the
##value of private_key will be used as the EKVS key.
##Paths accept a leading '~' or '~/' which are expanded to the user's home.
#ekvs_enable: false
#ekvs_server: 'https://ekvs.example.com'
#ekvs_project: 'my-project'
#ekvs_private_key: '~/.ssh/ekvs_key'
##Continuity integration (optional): register the deployed container as a
##backend on a Continuity load balancer pool. When continuity_enable is
##true, continuity_config and continuity_internal_port are required.
##continuity_config must point to a Continuity CLI configuration file
##(host/port/default_pool/auth_key). Note that continuity itself does not
##expand '~' and builds its endpoint by concatenation, so inside that file
##'host' must include the scheme (e.g. http://continuity.example.com) and
##'auth_key' must be an absolute path; the key must have no passphrase.
##continuity_internal_port is the port the container listens on: the server
##looks up the published Docker port for it.
##continuity_pool may be omitted if that file sets default_pool.
##continuity_private_key is optional and has NO fallback (unlike
##ekvs_private_key):
## - if set, the key is read here and sent to the server, which will copy
##   it into the project's working directory and rewrite auth_key in the
##   forwarded continuity_config to point at it;
## - if left empty, auth_key in continuity_config is assumed to already
##   point to a key present on the server, placed there manually.
##continuity_advertise_base overrides, for this project only, the server's
##own continuity_advertise_base: the base URL under which the container is
##reachable by continuity. Scheme included, no port and no path — the
##published container port is appended by the server.
#continuity_enable: false
#continuity_config: './continuity-client.yaml'
#continuity_private_key: '~/.ssh/continuity_key'
#continuity_pool: 'my-app.example.com'
#continuity_health_check_path: '/health'
#continuity_internal_port: '8080'
#continuity_remove_previous: true
#continuity_advertise_base: 'http://10.0.0.5'
`))
	return err
}
