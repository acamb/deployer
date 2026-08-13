package continuity

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// ConfigFileName is the name of the Continuity CLI configuration file
	// persisted for a project and passed to every `continuity -f` call.
	ConfigFileName = "config.yaml"
	// KeyFileName is the name of the private key persisted for a project on
	// path A (key managed by deployer).
	KeyFileName = "key"
)

// WriteProjectConfig persists under dir the Continuity CLI configuration of a
// project and returns the absolute path of the written configuration file.
//
// Two explicit paths, no automatic fallback (unlike EKVS):
//
//   - Path A (keyBytes not empty): the key is written to `key` with mode 0600
//     and the `auth_key` entry of the configuration is rewritten to point at
//     its absolute local path. Continuity does no `~` expansion and resolves
//     the path on the server, so an absolute path is the only safe choice.
//   - Path B (keyBytes empty): the configuration is persisted byte for byte
//     and no key file is written. Its `auth_key` must already point at a key
//     present on the server.
//
// Unlike EKVS the key is persisted instead of being created and removed per
// request, because the periodic reconciliation needs it long after the deploy
// that carried it, including across restarts of the server.
func WriteProjectConfig(dir string, cfgBytes, keyBytes []byte) (string, error) {
	if len(bytes.TrimSpace(cfgBytes)) == 0 {
		return "", errors.New("no continuity configuration was provided")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve continuity directory %s: %v", dir, err)
	}
	if err := os.MkdirAll(absDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create continuity directory %s: %v", absDir, err)
	}
	cfgPath := filepath.Join(absDir, ConfigFileName)

	if len(keyBytes) == 0 {
		// Path B: the configuration is authoritative as received.
		if err := writeFileAtomic(cfgPath, cfgBytes, 0600); err != nil {
			return "", err
		}
		return cfgPath, nil
	}

	// Path A: the key travels with the request and belongs to deployer.
	keyPath := filepath.Join(absDir, KeyFileName)
	if err := writeFileAtomic(keyPath, keyBytes, 0600); err != nil {
		return "", err
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(cfgBytes, &document); err != nil {
		return "", fmt.Errorf("cannot parse the continuity configuration: %v", err)
	}
	if document == nil {
		document = make(map[string]interface{})
	}
	document["auth_key"] = keyPath
	out, err := yaml.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("cannot serialize the continuity configuration: %v", err)
	}
	if err := writeFileAtomic(cfgPath, out, 0600); err != nil {
		return "", err
	}
	return cfgPath, nil
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory followed by a rename, so that a reader never observes a partially
// written file and a failed write never destroys the previous content.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file in %s: %v", dir, err)
	}
	tempPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}
	// Set the permissions before writing: on path A the file holds a private
	// key and must never be readable by others, not even briefly.
	if err := os.Chmod(tempPath, perm); err != nil {
		cleanup()
		return fmt.Errorf("cannot set permissions on %s: %v", tempPath, err)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("cannot write %s: %v", tempPath, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("cannot close %s: %v", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	return nil
}
