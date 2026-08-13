package main

import (
	"bytes"
	"context"
	"deployer/protocol"
	"deployer/server/continuity"
	serverVersion "deployer/server/version"
	"encoding/gob"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// fakeTransaction is one `server transaction` captured by fakeContinuityClient.
type fakeTransaction struct {
	cfgPath     string
	pool        string
	address     string
	healthCheck string
	removeUUID  string
}

// fakeRemoval is one `server del` captured by fakeContinuityClient.
type fakeRemoval struct {
	pool string
	uuid string
}

// fakeContinuityClient replaces the continuity CLI: the glue is exercised
// without the binary and without a continuity server.
type fakeContinuityClient struct {
	pool           *continuity.Pool
	poolErr        error
	transactionErr error
	removeErr      error

	poolConfigCalls int
	transactions    []fakeTransaction
	removals        []fakeRemoval
}

func (f *fakeContinuityClient) Transaction(_ context.Context, cfgPath, pool, address, healthCheck, removeUUID string) error {
	f.transactions = append(f.transactions, fakeTransaction{cfgPath, pool, address, healthCheck, removeUUID})
	return f.transactionErr
}

func (f *fakeContinuityClient) PoolConfig(_ context.Context, _, _ string) (*continuity.Pool, error) {
	f.poolConfigCalls++
	if f.poolErr != nil {
		return nil, f.poolErr
	}
	if f.pool == nil {
		return &continuity.Pool{}, nil
	}
	return f.pool, nil
}

func (f *fakeContinuityClient) RemoveServer(_ context.Context, _, pool, uuid string) error {
	f.removals = append(f.removals, fakeRemoval{pool, uuid})
	return f.removeErr
}

// fakePorts replaces `docker port`.
type fakePorts struct {
	ports []protocol.Port
	err   error
	calls []string
}

func (f *fakePorts) binding(name string, _ string) ([]protocol.Port, error) {
	f.calls = append(f.calls, name)
	return f.ports, f.err
}

// useFakeContinuity installs the fake CLI and the fake port resolution for the
// duration of a test.
func useFakeContinuity(t *testing.T, client continuityClient, ports *fakePorts) {
	t.Helper()
	previousClient, previousPorts := newContinuityClient, continuityPortsBinding
	newContinuityClient = func() continuityClient { return client }
	continuityPortsBinding = ports.binding
	t.Cleanup(func() {
		newContinuityClient, continuityPortsBinding = previousClient, previousPorts
	})
}

func publishedPorts() *fakePorts {
	return &fakePorts{ports: []protocol.Port{
		{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
	}}
}

// continuityBackend builds a backend as continuity would return it, from the
// `http://host:port` form used everywhere else in the glue.
func continuityBackend(id, address string) continuity.ServerHost {
	host, _ := strings.CutPrefix(address, "http://")
	return continuity.ServerHost{
		Id:           id,
		Address:      continuity.URL{Scheme: "http", Host: host},
		ServerStatus: "Healthy",
	}
}

// continuityRequest is a Deploy request of a project with the integration
// enabled, on path A (the key travels with the request).
func continuityRequest(name string) protocol.Request {
	return protocol.Request{
		Version:                   serverVersion.Version,
		Command:                   protocol.Deploy,
		Name:                      name,
		ContinuityEnable:          true,
		ContinuityConfig:          []byte("host: http://continuity.example.com\nport: 8090\n"),
		ContinuityPrivateKey:      []byte("PRIVATE KEY"),
		ContinuityPool:            "my-app.example.com",
		ContinuityHealthCheckPath: "/health",
		ContinuityInternalPort:    "80",
		ContinuityRemovePrevious:  true,
		ContinuityAdvertiseBase:   "http://10.0.0.5",
	}
}

func TestResolveAdvertiseBase(t *testing.T) {
	setupTestEnvironment(t)

	hostname, err := os.Hostname()
	require.NoError(t, err)

	t.Run("The client override wins", func(t *testing.T) {
		config.ContinuityAdvertiseBase = "http://from-server-config"
		base, err := resolveAdvertiseBase("https://10.0.0.5")
		require.NoError(t, err)
		assert.Equal(t, "https://10.0.0.5", base)
	})

	t.Run("The server configuration is the second choice", func(t *testing.T) {
		config.ContinuityAdvertiseBase = "http://10.0.0.9"
		base, err := resolveAdvertiseBase("")
		require.NoError(t, err)
		assert.Equal(t, "http://10.0.0.9", base)
	})

	t.Run("The hostname is the last resort", func(t *testing.T) {
		config.ContinuityAdvertiseBase = ""
		base, err := resolveAdvertiseBase("   ")
		require.NoError(t, err)
		assert.Equal(t, "http://"+hostname, base)
	})

	t.Run("A trailing slash never reaches the address", func(t *testing.T) {
		config.ContinuityAdvertiseBase = "http://10.0.0.9/"
		base, err := resolveAdvertiseBase("")
		require.NoError(t, err)
		assert.Equal(t, "http://10.0.0.9", base)

		base, err = resolveAdvertiseBase("http://10.0.0.5/")
		require.NoError(t, err)
		assert.Equal(t, "http://10.0.0.5", base)
	})
}

func TestContainerName(t *testing.T) {
	assert.Equal(t, "myapp", containerName("myapp", ""))
	assert.Equal(t, "myapp-2", containerName("myapp", "2"))
}

func TestRegisterBackendIsANoOpWhenDisabled(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	ports := publishedPorts()
	useFakeContinuity(t, client, ports)

	require.NoError(t, registerBackend(protocol.Request{Command: protocol.Deploy, Name: "plain-app"}))

	assert.Empty(t, client.transactions)
	assert.Empty(t, ports.calls)
	_, err := os.Stat(continuity.Dir(config.WorkingDirectory, "plain-app"))
	assert.True(t, os.IsNotExist(err), "no continuity directory must be created for a project without the integration")
}

func TestRegisterBackendPublishesTheContainer(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	ports := publishedPorts()
	useFakeContinuity(t, client, ports)

	require.NoError(t, registerBackend(continuityRequest("myapp")))

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	cfgPath := filepath.Join(dir, continuity.ConfigFileName)

	// The published address is the advertise base plus the *host* port, the
	// ephemeral one Docker assigned to the internal port of the container.
	require.Len(t, client.transactions, 1)
	assert.Equal(t, fakeTransaction{
		cfgPath:     cfgPath,
		pool:        "my-app.example.com",
		address:     "http://10.0.0.5:32768",
		healthCheck: "/health",
		// First deploy: there is no previous backend to remove.
		removeUUID: "",
	}, client.transactions[0])
	// A single pool config, taken before the transaction.
	assert.Equal(t, 1, client.poolConfigCalls)
	assert.Equal(t, []string{"myapp"}, ports.calls)

	// Path A: the key is persisted and auth_key points at it.
	document := map[string]interface{}{}
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(data, &document))
	assert.Equal(t, filepath.Join(dir, continuity.KeyFileName), document["auth_key"])
	assert.Equal(t, "http://continuity.example.com", document["host"])

	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "myapp", state.Project)
	assert.Equal(t, "my-app.example.com", state.Pool)
	assert.Equal(t, "/health", state.HealthCheckPath)
	assert.Equal(t, "80", state.InternalPort)
	assert.True(t, state.RemovePrevious)
	assert.Equal(t, "http://10.0.0.5", state.AdvertiseBase)
	assert.Equal(t, "http://10.0.0.5:32768", state.LastAddress)
}

func TestRegisterBackendKeepsTheStateOutOfTheRevision(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	ports := publishedPorts()
	useFakeContinuity(t, client, ports)

	request := continuityRequest("myapp")
	request.Revision = "2"
	require.NoError(t, registerBackend(request))

	// The container carries the revision, the state does not: it tracks the
	// single active backend of the project, so deploying a new revision
	// replaces the backend of the previous one.
	assert.Equal(t, []string{"myapp-2"}, ports.calls)
	state, err := continuity.LoadState(continuity.Dir(config.WorkingDirectory, "myapp"))
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "http://10.0.0.5:32768", state.LastAddress)

	_, err = os.Stat(filepath.Join(config.WorkingDirectory, "myapp", "2", continuity.DirName))
	assert.True(t, os.IsNotExist(err), "the state must never live under a revision")
}

func TestRegisterBackendRemovesThePreviousBackend(t *testing.T) {
	testCases := []struct {
		name           string
		removePrevious bool
		lastAddress    string
		pool           *continuity.Pool
		expectUUID     string
	}{
		{
			name:           "Previous backend resolved by address",
			removePrevious: true,
			lastAddress:    "http://10.0.0.5:32000",
			pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
				continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
			}},
			expectUUID: "cbfca8b3",
		},
		{
			// Correction 3: an unknown UUID makes the whole transaction fail
			// before the new backend is added, so the flag is omitted.
			name:           "Previous address no longer in the pool",
			removePrevious: true,
			lastAddress:    "http://10.0.0.5:32000",
			pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
				continuityBackend("cbfca8b3", "http://10.0.0.9:32000"),
			}},
			expectUUID: "",
		},
		{
			name:           "Removal disabled by the project",
			removePrevious: false,
			lastAddress:    "http://10.0.0.5:32000",
			pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
				continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
			}},
			expectUUID: "",
		},
		{
			name:           "Nothing published yet",
			removePrevious: true,
			lastAddress:    "",
			pool:           &continuity.Pool{},
			expectUUID:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestEnvironment(t)
			client := &fakeContinuityClient{pool: tc.pool}
			useFakeContinuity(t, client, publishedPorts())

			dir := continuity.Dir(config.WorkingDirectory, "myapp")
			require.NoError(t, continuity.SaveState(dir, &continuity.State{
				Project:      "myapp",
				Pool:         "my-app.example.com",
				InternalPort: "80",
				LastAddress:  tc.lastAddress,
			}))

			request := continuityRequest("myapp")
			request.ContinuityRemovePrevious = tc.removePrevious
			require.NoError(t, registerBackend(request))

			require.Len(t, client.transactions, 1)
			assert.Equal(t, tc.expectUUID, client.transactions[0].removeUUID)
			// The removal is part of the transaction, never a separate call.
			assert.Empty(t, client.removals)

			state, err := continuity.LoadState(dir)
			require.NoError(t, err)
			assert.Equal(t, "http://10.0.0.5:32768", state.LastAddress)
		})
	}
}

func TestRegisterBackendWithoutPublishedPort(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, &fakePorts{ports: []protocol.Port{
		{LocalPort: "443", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
	}})

	err := registerBackend(continuityRequest("myapp"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "80/tcp is not published")
	assert.Empty(t, client.transactions)

	// The deploy parameters are persisted anyway: the reconciliation needs
	// them to publish the project as soon as the port shows up.
	state, err := continuity.LoadState(continuity.Dir(config.WorkingDirectory, "myapp"))
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "80", state.InternalPort)
	assert.Empty(t, state.LastAddress)
}

func TestRegisterBackendKeepsThePreviousAddressWhenTheTransactionFails(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{transactionErr: errors.New("the continuity transaction was rolled back: new server is not healthy")}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:      "myapp",
		Pool:         "my-app.example.com",
		InternalPort: "80",
		LastAddress:  "http://10.0.0.5:32000",
	}))

	err := registerBackend(continuityRequest("myapp"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rolled back")

	// The address of the backend still live on continuity must survive, or it
	// could never be removed again.
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, "http://10.0.0.5:32000", state.LastAddress)
}

func TestRegisterBackendWithoutConfiguration(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())

	request := continuityRequest("myapp")
	request.ContinuityConfig = nil

	err := registerBackend(request)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no continuity configuration")
	assert.Empty(t, client.transactions)
}

func TestDeregisterBackend(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:      "myapp",
		Pool:         "my-app.example.com",
		InternalPort: "80",
		LastAddress:  "http://10.0.0.5:32768",
	}))

	require.NoError(t, deregisterBackend("myapp"))

	assert.Equal(t, []fakeRemoval{{pool: "my-app.example.com", uuid: "cbfca8b3"}}, client.removals)

	// The project stays in the registry with its deploy parameters: only the
	// ownership of a backend is dropped, so a container coming back up on its
	// own is published again by the reconciliation.
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Empty(t, state.LastAddress)
	assert.Equal(t, "my-app.example.com", state.Pool)
	assert.Equal(t, "80", state.InternalPort)
}

func TestDeregisterBackendAlreadyRemoved(t *testing.T) {
	setupTestEnvironment(t)
	// The backend was removed by hand: nothing to call, but the state must
	// still be cleared.
	client := &fakeContinuityClient{pool: &continuity.Pool{}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:     "myapp",
		Pool:        "my-app.example.com",
		LastAddress: "http://10.0.0.5:32768",
	}))

	require.NoError(t, deregisterBackend("myapp"))

	assert.Empty(t, client.removals)
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	assert.Empty(t, state.LastAddress)
}

func TestDeregisterBackendKeepsTheAddressOnFailure(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{
		pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
		}},
		removeErr: errors.New("exit status 1"),
	}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:     "myapp",
		Pool:        "my-app.example.com",
		LastAddress: "http://10.0.0.5:32768",
	}))

	err = deregisterBackend("myapp")
	require.Error(t, err)

	// The backend is still there: the next reconciliation pass must retry.
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, "http://10.0.0.5:32768", state.LastAddress)
}

func TestDeregisterBackendWithoutState(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())

	// A project without the integration at all.
	require.NoError(t, deregisterBackend("plain-app"))
	assert.Equal(t, 0, client.poolConfigCalls)

	// A project whose backend was already removed, the state left by a
	// previous stop: nothing is published, nothing to remove.
	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{Project: "myapp", Pool: "my-app.example.com"}))
	require.NoError(t, deregisterBackend("myapp"))
	assert.Equal(t, 0, client.poolConfigCalls)
}

// handleContinuityRequest encodes a request, runs handleRequest and returns
// the response, like the helper of TestHandleRequest_Commands.
func handleContinuityRequest(t *testing.T, request protocol.Request) protocol.Response {
	t.Helper()
	channel := &MockSSHChannel{Buffer: &bytes.Buffer{}, closed: false}
	encoder := gob.NewEncoder(channel)
	decoder := gob.NewDecoder(channel)
	require.NoError(t, encoder.Encode(request))
	handleRequest(channel)
	var response protocol.Response
	require.NoError(t, decoder.Decode(&response))
	return response
}

func TestStartStaysOkWhenContinuityFails(t *testing.T) {
	setupTestEnvironment(t)
	// A misconfigured continuity_bin: the container is up, the deploy
	// succeeded, so the problem can only be a warning, never a Ko.
	config.ContinuityBin = filepath.Join(t.TempDir(), "there-is-no-continuity-here")
	previousPorts := continuityPortsBinding
	continuityPortsBinding = publishedPorts().binding
	t.Cleanup(func() { continuityPortsBinding = previousPorts })

	request := continuityRequest("warning-app")
	request.Command = protocol.Start
	require.NoError(t, os.MkdirAll(filepath.Join(config.WorkingDirectory, request.Name), 0770))

	TestingMode = true
	response := handleContinuityRequest(t, request)
	TestingMode = false

	assert.Equal(t, protocol.Ok, response.Status)
	assert.Contains(t, response.Message, "started successfully")
	assert.Contains(t, response.Message, "continuity warning")
}

func TestRestartRepublishesTheBackend(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
	}}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "restart-app")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:      "restart-app",
		Pool:         "my-app.example.com",
		InternalPort: "80",
		LastAddress:  "http://10.0.0.5:32000",
	}))

	request := continuityRequest("restart-app")
	request.Command = protocol.Restart
	require.NoError(t, os.MkdirAll(filepath.Join(config.WorkingDirectory, request.Name), 0770))

	TestingMode = true
	response := handleContinuityRequest(t, request)
	TestingMode = false

	assert.Equal(t, protocol.Ok, response.Status)
	assert.NotContains(t, response.Message, "continuity warning")
	// The ephemeral port changes at every restart, hence the republication.
	require.Len(t, client.transactions, 1)
	assert.Equal(t, "http://10.0.0.5:32768", client.transactions[0].address)
	assert.Equal(t, "cbfca8b3", client.transactions[0].removeUUID)
}

func TestStopDeregistersBeforeDeletingTheFiles(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "stop-app")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:      "stop-app",
		Pool:         "my-app.example.com",
		InternalPort: "80",
		LastAddress:  "http://10.0.0.5:32768",
	}))

	TestingMode = true
	response := handleContinuityRequest(t, protocol.Request{
		Version:     serverVersion.Version,
		Command:     protocol.Stop,
		Name:        "stop-app",
		DeleteFiles: true,
	})
	TestingMode = false

	assert.Equal(t, protocol.Ok, response.Status)
	assert.Contains(t, response.Message, "stopped successfully")
	// The stop request carries no continuity field: the backend is resolved
	// from the persisted state, and removed before RemoveAll wipes it.
	assert.Equal(t, []fakeRemoval{{pool: "my-app.example.com", uuid: "cbfca8b3"}}, client.removals)
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "the working directory of the project must be gone")
}

func TestStopStaysOkWhenContinuityFails(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{poolErr: errors.New("exit status 1")}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "stop-app")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:     "stop-app",
		Pool:        "my-app.example.com",
		LastAddress: "http://10.0.0.5:32768",
	}))

	TestingMode = true
	response := handleContinuityRequest(t, protocol.Request{
		Version: serverVersion.Version,
		Command: protocol.Stop,
		Name:    "stop-app",
	})
	TestingMode = false

	assert.Equal(t, protocol.Ok, response.Status)
	assert.Contains(t, response.Message, "stopped successfully")
	assert.Contains(t, response.Message, "continuity warning")
}
