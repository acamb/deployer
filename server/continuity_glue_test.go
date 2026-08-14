package main

import (
	"bytes"
	"context"
	"deployer/protocol"
	"deployer/server/continuity"
	serverVersion "deployer/server/version"
	"encoding/gob"
	"encoding/json"
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

// fakeAdd is one `server add` captured by fakeContinuityClient.
type fakeAdd struct {
	cfgPath     string
	pool        string
	address     string
	healthCheck string
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
	addErr         error
	removeErr      error

	poolConfigCalls int
	transactions    []fakeTransaction
	adds            []fakeAdd
	removals        []fakeRemoval
}

func (f *fakeContinuityClient) Transaction(_ context.Context, cfgPath, pool, address, healthCheck, removeUUID string) error {
	f.transactions = append(f.transactions, fakeTransaction{cfgPath, pool, address, healthCheck, removeUUID})
	return f.transactionErr
}

func (f *fakeContinuityClient) AddServer(_ context.Context, cfgPath, pool, address, healthCheck string) error {
	f.adds = append(f.adds, fakeAdd{cfgPath, pool, address, healthCheck})
	return f.addErr
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
	// First deploy: nothing to remove, so a plain add is used, not a
	// transaction (which would fail against an empty pool).
	assert.Empty(t, client.transactions)
	require.Len(t, client.adds, 1)
	assert.Equal(t, fakeAdd{
		cfgPath:     cfgPath,
		pool:        "my-app.example.com",
		address:     "http://10.0.0.5:32768",
		healthCheck: "/health",
	}, client.adds[0])
	// A single pool config, taken before the publication.
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

			if tc.expectUUID != "" {
				// A previous backend was resolved: the transaction adds the new
				// one and drops it atomically.
				require.Len(t, client.transactions, 1)
				assert.Equal(t, tc.expectUUID, client.transactions[0].removeUUID)
				assert.Empty(t, client.adds)
			} else {
				// Nothing to remove: a plain add, never a transaction.
				assert.Empty(t, client.transactions)
				require.Len(t, client.adds, 1)
				assert.Equal(t, "http://10.0.0.5:32768", client.adds[0].address)
			}
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
	// The previous backend is in the pool, so a transaction is used to replace
	// it, and it is the transaction that fails here.
	client := &fakeContinuityClient{
		pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
		}},
		transactionErr: errors.New("the continuity transaction was rolled back: new server is not healthy"),
	}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:        "myapp",
		Pool:           "my-app.example.com",
		InternalPort:   "80",
		RemovePrevious: true,
		LastAddress:    "http://10.0.0.5:32000",
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

func TestStartFailsWhenContinuityFails(t *testing.T) {
	setupTestEnvironment(t)
	// A misconfigured continuity_bin makes the publication fail. Adding the
	// container to the load balancer is part of a successful deploy, so the
	// response is a Ko; there is no previous revision to fall back to, so the
	// container is left running for the reconciliation to retry.
	config.ContinuityBin = filepath.Join(t.TempDir(), "there-is-no-continuity-here")
	previousPorts := continuityPortsBinding
	continuityPortsBinding = publishedPorts().binding
	t.Cleanup(func() { continuityPortsBinding = previousPorts })

	request := continuityRequest("failing-app")
	request.Command = protocol.Start
	require.NoError(t, os.MkdirAll(filepath.Join(config.WorkingDirectory, request.Name), 0770))

	TestingMode = true
	response := handleContinuityRequest(t, request)
	TestingMode = false

	assert.Equal(t, protocol.Ko, response.Status)
	assert.Contains(t, response.Message, "Load balancer registration failed")
	assert.Contains(t, response.Message, "will be retried")
}

// perContainerPorts is a name-aware `docker port`: it lets a test say that one
// container publishes a port while another one is down.
type perContainerPorts struct {
	byName map[string][]protocol.Port
	calls  []string
}

func (p *perContainerPorts) binding(name string, _ string) ([]protocol.Port, error) {
	p.calls = append(p.calls, name)
	return p.byName[name], nil
}

// installTeardown replaces the container teardown with a recorder, so a rollback
// can be exercised without Docker.
func installTeardown(t *testing.T) *[]protocol.Request {
	t.Helper()
	var tornDown []protocol.Request
	previous := teardownContainer
	teardownContainer = func(request protocol.Request) error {
		tornDown = append(tornDown, request)
		return nil
	}
	t.Cleanup(func() { teardownContainer = previous })
	return &tornDown
}

func TestFinalizeBackendSucceeds(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())
	tornDown := installTeardown(t)

	result := finalizeBackend(continuityRequest("myapp"))

	assert.NoError(t, result.err)
	assert.False(t, result.rolledBack)
	assert.Empty(t, *tornDown)
}

func TestFinalizeBackendRollsBackToThePreviousRevision(t *testing.T) {
	setupTestEnvironment(t)
	// The previous revision is published, so a transaction is used to replace
	// it, and the transaction rolls back (the new backend never gets healthy).
	client := &fakeContinuityClient{
		pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
		}},
		transactionErr: errors.New("the continuity transaction was rolled back: new server is not healthy"),
	}
	useFakeContinuity(t, client, publishedPorts())
	tornDown := installTeardown(t)

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:        "myapp",
		Container:      "myapp-1",
		Pool:           "my-app.example.com",
		InternalPort:   "80",
		RemovePrevious: true,
		AdvertiseBase:  "http://10.0.0.5",
		LastAddress:    "http://10.0.0.5:32000",
	}))

	request := continuityRequest("myapp")
	request.Revision = "2"
	result := finalizeBackend(request)

	require.Error(t, result.err)
	assert.True(t, result.rolledBack)
	assert.Equal(t, "myapp-1", result.keptRevision)
	// The new revision container was terminated exactly once.
	require.Len(t, *tornDown, 1)
	assert.Equal(t, "2", (*tornDown)[0].Revision)

	// The state was restored to the previous revision: the reconciliation must
	// keep myapp-1 published and never see the new, dead, container.
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, "myapp-1", state.Container)
	assert.Equal(t, "http://10.0.0.5:32000", state.LastAddress)
}

func TestFinalizeBackendLeavesTheContainerRunningWithoutAPreviousRevision(t *testing.T) {
	setupTestEnvironment(t)
	// First deploy: nothing published yet, an add is used and it fails. There is
	// no previous revision to keep, so the container is left running.
	client := &fakeContinuityClient{addErr: errors.New("exit status 1")}
	useFakeContinuity(t, client, publishedPorts())
	tornDown := installTeardown(t)

	result := finalizeBackend(continuityRequest("myapp"))

	require.Error(t, result.err)
	assert.False(t, result.rolledBack)
	assert.Empty(t, *tornDown)
}

func TestFinalizeBackendDoesNotRollBackTheSameRevision(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{
		pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
		}},
		transactionErr: errors.New("rolled back"),
	}
	useFakeContinuity(t, client, publishedPorts())
	tornDown := installTeardown(t)

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:        "myapp",
		Container:      "myapp-2",
		Pool:           "my-app.example.com",
		InternalPort:   "80",
		RemovePrevious: true,
		LastAddress:    "http://10.0.0.5:32000",
	}))

	// Redeploying the same revision replaces it in place: the old container was
	// already stopped by the deploy, there is no distinct previous revision that
	// could keep serving, so no rollback.
	request := continuityRequest("myapp")
	request.Revision = "2"
	result := finalizeBackend(request)

	require.Error(t, result.err)
	assert.False(t, result.rolledBack)
	assert.Empty(t, *tornDown)
}

func TestReconcileKeepsThePreviousRevisionAfterARollback(t *testing.T) {
	setupTestEnvironment(t)
	// The state as finalizeBackend restored it after a rollback: the previous
	// revision, myapp-1, is the active one, published at 32000.
	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project:       "myapp",
		Container:     "myapp-1",
		Pool:          "my-app.example.com",
		InternalPort:  "80",
		AdvertiseBase: "http://10.0.0.5",
		LastAddress:   "http://10.0.0.5:32000",
	}))

	// The previous revision still publishes its port; the rolled back one is gone.
	ports := &perContainerPorts{byName: map[string][]protocol.Port{
		"myapp-1": {{LocalPort: "80", BindPort: "32000", Protocol: "tcp", Address: "0.0.0.0"}},
	}}
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
	}}}
	previousClient, previousPorts := newContinuityClient, continuityPortsBinding
	newContinuityClient = func() continuityClient { return client }
	continuityPortsBinding = ports.binding
	t.Cleanup(func() { newContinuityClient, continuityPortsBinding = previousClient, previousPorts })

	require.NoError(t, reconcileProject(client, "myapp"))

	// The previous backend is healthy at its expected address: nothing to repair,
	// and above all nothing removed.
	assert.Empty(t, client.removals)
	assert.Empty(t, client.transactions)
	assert.Empty(t, client.adds)
	assert.Equal(t, []string{"myapp-1"}, ports.calls)
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, "http://10.0.0.5:32000", state.LastAddress)
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

func TestLbStatusReturnsThePoolBackends(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{
		Hostname: "my-app.example.com",
		UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
		},
		ConditionalServers: []continuity.ServerHost{
			continuityBackend("aa11bb22", "http://10.0.0.9:40000"),
		},
	}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{
		Project: "myapp",
		Pool:    "my-app.example.com",
	}))

	status, err := lbStatus("myapp")
	require.NoError(t, err)

	assert.Equal(t, "my-app.example.com", status.Hostname)
	require.Len(t, status.Backends, 2)
	// Unconditional backends come first and are flagged as such.
	assert.Equal(t, protocol.LbBackend{
		Address:         "http://10.0.0.5:32768",
		Status:          "Healthy",
		HealthCheckPath: "",
		Conditional:     false,
	}, status.Backends[0])
	assert.Equal(t, "http://10.0.0.9:40000", status.Backends[1].Address)
	assert.True(t, status.Backends[1].Conditional)
	assert.Equal(t, 1, client.poolConfigCalls)
}

func TestLbStatusWithoutState(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())

	// The project was never deployed with the integration enabled.
	_, err := lbStatus("never-deployed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
	assert.Equal(t, 0, client.poolConfigCalls)
}

func TestLbStatusOverTheProtocol(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{
		Hostname: "my-app.example.com",
		UnconditionalServers: []continuity.ServerHost{
			continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
		},
	}}
	useFakeContinuity(t, client, publishedPorts())

	dir := continuity.Dir(config.WorkingDirectory, "myapp")
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, &continuity.State{Project: "myapp", Pool: "my-app.example.com"}))

	response := handleContinuityRequest(t, protocol.Request{
		Version: serverVersion.Version,
		Command: protocol.LbStatus,
		Name:    "myapp",
	})

	require.Equal(t, protocol.Ok, response.Status)
	var status protocol.LbStatusResponse
	require.NoError(t, json.Unmarshal([]byte(response.Message), &status))
	assert.Equal(t, "my-app.example.com", status.Hostname)
	require.Len(t, status.Backends, 1)
	assert.Equal(t, "http://10.0.0.5:32768", status.Backends[0].Address)
}

func TestLbStatusOverTheProtocolWithoutState(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())

	response := handleContinuityRequest(t, protocol.Request{
		Version: serverVersion.Version,
		Command: protocol.LbStatus,
		Name:    "never-deployed",
	})

	assert.Equal(t, protocol.Ko, response.Status)
	assert.Contains(t, response.Message, "not configured")
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
