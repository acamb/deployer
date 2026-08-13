package main

import (
	"deployer/protocol"
	"deployer/server/continuity"
	serverVersion "deployer/server/version"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanContinuityProjects(t *testing.T) {
	workingDirectory := t.TempDir()

	// Two projects with a valid state, one of them with revisions: the state
	// lives at the project level, so the revision directories must not confuse
	// the scan.
	for _, project := range []string{"alpha", "beta"} {
		require.NoError(t, continuity.SaveState(continuity.Dir(workingDirectory, project), &continuity.State{
			Project:      project,
			Pool:         "my-app.example.com",
			InternalPort: "80",
			LastAddress:  "http://10.0.0.5:32768",
		}))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(workingDirectory, "beta", "1"), 0770))

	// A project deployed without the integration.
	require.NoError(t, os.MkdirAll(filepath.Join(workingDirectory, "plain"), 0770))

	// A project whose state is unreadable: it is skipped, not fatal.
	corrupted := continuity.Dir(workingDirectory, "corrupted")
	require.NoError(t, os.MkdirAll(corrupted, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(corrupted, continuity.StateFileName), []byte("{not json"), 0600))

	assert.Equal(t, []string{"alpha", "beta"}, scanContinuityProjects(workingDirectory))
}

func TestScanContinuityProjectsOnAnEmptyWorkingDirectory(t *testing.T) {
	assert.Empty(t, scanContinuityProjects(t.TempDir()))
}

func TestLoadContinuityRegistry(t *testing.T) {
	setupTestEnvironment(t)
	continuityProjects.replace([]string{"stale"})

	require.NoError(t, continuity.SaveState(continuity.Dir(config.WorkingDirectory, "alpha"), &continuity.State{
		Project: "alpha",
		Pool:    "my-app.example.com",
	}))

	loadContinuityRegistry(config.WorkingDirectory)

	// The scan replaces the registry, it does not merge into it.
	assert.Equal(t, []string{"alpha"}, continuityProjects.list())
}

func TestProjectRegistryAdd(t *testing.T) {
	registry := newProjectRegistry()
	registry.add("beta")
	registry.add("alpha")
	registry.add("beta")

	assert.Equal(t, []string{"alpha", "beta"}, registry.list())
}

func TestDeployRegistersTheProject(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())

	request := continuityRequest("registry-app")
	request.Command = protocol.Start
	require.NoError(t, os.MkdirAll(filepath.Join(config.WorkingDirectory, request.Name), 0770))

	TestingMode = true
	response := handleContinuityRequest(t, request)
	TestingMode = false

	require.Equal(t, protocol.Ok, response.Status)
	// A deploy arriving after the startup scan must join the registry, or the
	// project would be reconciled only after the next restart of the server.
	assert.Equal(t, []string{"registry-app"}, continuityProjects.list())
}

func TestNotReadyRefusesEveryRequest(t *testing.T) {
	setupTestEnvironment(t)
	ready.Store(false)
	t.Cleanup(func() { ready.Store(true) })

	commands := []protocol.Command{protocol.Deploy, protocol.Start, protocol.Stop, protocol.Ports, protocol.Revisions}
	for _, command := range commands {
		response := handleContinuityRequest(t, protocol.Request{
			Version: serverVersion.Version,
			Command: command,
			Name:    "not-ready-app",
		})
		assert.Equal(t, protocol.NotReady, response.Status, "command %v", command)
	}

	// The gate comes before the version check: a client of the wrong version
	// gets the invitation to retry, not a mismatch it cannot act upon.
	response := handleContinuityRequest(t, protocol.Request{
		Version: "some-other-version",
		Command: protocol.Deploy,
		Name:    "not-ready-app",
	})
	assert.Equal(t, protocol.NotReady, response.Status)
}
