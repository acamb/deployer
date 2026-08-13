// Package continuity holds the server side of the Continuity load balancer
// integration: the per-project state persisted under the working directory,
// the helpers that write the Continuity CLI configuration of a project, and
// the pure functions used to compute the address to publish as a backend.
//
// Everything in this package is deliberately free of Docker and network
// access so that it can be unit tested in isolation.
package continuity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DirName is the name of the per-project directory holding the
	// Continuity state. It always lives at the project level, never under a
	// revision, so that the state tracks the single active backend of the
	// project and deploying a new revision replaces the previous one.
	DirName = ".continuity"
	// StateFileName is the name of the JSON file holding the State.
	StateFileName = "state.json"
)

// State is what the server persists for every project with the Continuity
// integration enabled. It is reloaded at startup to rebuild the in-memory
// registry of projects to reconcile.
type State struct {
	// Deploy parameters: they only ever arrive with a request, are not
	// derivable from Docker nor from Continuity, and are needed by every
	// reconciliation pass, including after a restart of the server.
	Project         string `json:"project"`
	Pool            string `json:"pool"`
	HealthCheckPath string `json:"health_check_path"`
	InternalPort    string `json:"internal_port"`
	RemovePrevious  bool   `json:"remove_previous"`
	AdvertiseBase   string `json:"advertise_base"`

	// Ownership: with ephemeral Docker ports the *previous* address is not
	// derivable from `docker port`, and Continuity offers no field (name,
	// label, tag) where the ownership of a backend could be marked, so the
	// address of the backend registered for this project is tracked here.
	LastAddress string `json:"last_address"`
}

// Dir returns the directory holding the Continuity state of a project. The
// revision is deliberately not part of the path (see State.LastAddress).
func Dir(workingDirectory, project string) string {
	return filepath.Join(workingDirectory, project, DirName)
}

// LoadState reads the state stored in dir. A missing file is not an error:
// it simply means the project has no Continuity state yet, and (nil, nil) is
// returned.
func LoadState(dir string) (*State, error) {
	path := filepath.Join(dir, StateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read continuity state %s: %v", path, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("cannot parse continuity state %s: %v", path, err)
	}
	return &state, nil
}

// SaveState writes the state to dir, creating it if needed. The file is
// written atomically so that a crash or a concurrent reconciliation pass can
// never observe a truncated state.json.
func SaveState(dir string, state *State) error {
	if state == nil {
		return errors.New("cannot save a nil continuity state")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create continuity directory %s: %v", dir, err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot serialize continuity state: %v", err)
	}
	return writeFileAtomic(filepath.Join(dir, StateFileName), append(data, '\n'), 0600)
}

// UpdateDeployParams overwrites the deploy parameters of the state stored in
// dir with those carried by params and saves the result. LastAddress is never
// taken from params: it is owned by the register/deregister flow and must
// survive a redeploy, otherwise the previous backend could no longer be
// identified on Continuity.
func UpdateDeployParams(dir string, params State) (*State, error) {
	current, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	lastAddress := ""
	if current != nil {
		lastAddress = current.LastAddress
	}
	merged := params
	merged.LastAddress = lastAddress
	if err := SaveState(dir, &merged); err != nil {
		return nil, err
	}
	return &merged, nil
}
