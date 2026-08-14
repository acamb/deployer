package main

import (
	"deployer/protocol"
	"deployer/server/continuity"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerContinuityProject writes the configuration and the state of a project
// with the integration enabled, and puts it in the registry, exactly as a
// deploy followed by a restart of the server would leave it.
func registerContinuityProject(t *testing.T, state *continuity.State) string {
	t.Helper()
	dir := continuity.Dir(config.WorkingDirectory, state.Project)
	_, err := continuity.WriteProjectConfig(dir, []byte("host: http://continuity.example.com\n"), nil)
	require.NoError(t, err)
	require.NoError(t, continuity.SaveState(dir, state))
	continuityProjects.add(state.Project)
	return dir
}

// reconciledState is the state of a project once a pass is over.
func reconciledState(t *testing.T, dir string) *continuity.State {
	t.Helper()
	state, err := continuity.LoadState(dir)
	require.NoError(t, err)
	require.NotNil(t, state)
	return state
}

func publishedProject(project string) *continuity.State {
	return &continuity.State{
		Project:        project,
		Pool:           "my-app.example.com",
		InternalPort:   "80",
		RemovePrevious: true,
		AdvertiseBase:  "http://10.0.0.5",
		LastAddress:    "http://10.0.0.5:32768",
	}
}

func TestReconcileLeavesAHealthyBackendAlone(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	useFakeContinuity(t, client, publishedPorts())
	dir := registerContinuityProject(t, publishedProject("steady-app"))

	reconcileContinuity()

	assert.Equal(t, 1, client.poolConfigCalls)
	assert.Empty(t, client.transactions)
	assert.Empty(t, client.removals)
	assert.Equal(t, "http://10.0.0.5:32768", reconciledState(t, dir).LastAddress)
}

func TestReconcileRepublishesAfterAPortChange(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32000"),
	}}}
	useFakeContinuity(t, client, publishedPorts())

	// The container came back on a different ephemeral port, without any
	// deploy: the backend published for the old one is now a dead address.
	state := publishedProject("moved-app")
	state.LastAddress = "http://10.0.0.5:32000"
	dir := registerContinuityProject(t, state)

	reconcileContinuity()

	require.Len(t, client.transactions, 1)
	assert.Equal(t, "http://10.0.0.5:32768", client.transactions[0].address)
	// The UUID is resolved from the old address on the pool configuration read
	// before the transaction, never from a stored one.
	assert.Equal(t, "cbfca8b3", client.transactions[0].removeUUID)
	assert.Equal(t, "http://10.0.0.5:32768", reconciledState(t, dir).LastAddress)
}

func TestReconcileOmitsAPreviousBackendNoLongerInThePool(t *testing.T) {
	setupTestEnvironment(t)
	// Somebody removed the backend by hand: the pool knows nothing about the
	// address the state still points at.
	client := &fakeContinuityClient{pool: &continuity.Pool{}}
	useFakeContinuity(t, client, publishedPorts())

	state := publishedProject("orphan-app")
	state.LastAddress = "http://10.0.0.5:31000"
	dir := registerContinuityProject(t, state)

	reconcileContinuity()

	require.Len(t, client.transactions, 1)
	assert.Equal(t, "http://10.0.0.5:32768", client.transactions[0].address)
	// An unknown UUID would make the whole transaction fail before adding the
	// new backend, so the flag is simply omitted.
	assert.Empty(t, client.transactions[0].removeUUID)
	assert.Equal(t, "http://10.0.0.5:32768", reconciledState(t, dir).LastAddress)
}

func TestReconcilePublishesAContainerBackUp(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{}}
	useFakeContinuity(t, client, publishedPorts())

	// The state a stop leaves behind: the project is still registered, nothing
	// is published for it. A container coming back on its own (a restart policy
	// of Docker, a `docker start` by hand) has to be published again.
	state := publishedProject("back-up-app")
	state.LastAddress = ""
	dir := registerContinuityProject(t, state)

	reconcileContinuity()

	require.Len(t, client.transactions, 1)
	assert.Equal(t, "http://10.0.0.5:32768", client.transactions[0].address)
	assert.Empty(t, client.transactions[0].removeUUID)
	assert.Equal(t, "http://10.0.0.5:32768", reconciledState(t, dir).LastAddress)
}

func TestReconcileRemovesTheBackendOfAStoppedContainer(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	// The container is there but publishes nothing any more: it is down.
	useFakeContinuity(t, client, &fakePorts{})
	dir := registerContinuityProject(t, publishedProject("stopped-app"))

	reconcileContinuity()

	require.Len(t, client.removals, 1)
	assert.Equal(t, "cbfca8b3", client.removals[0].uuid)
	assert.Empty(t, client.transactions, "a container that is down must never be published again")
	assert.Empty(t, reconciledState(t, dir).LastAddress)
}

func TestReconcileIgnoresAStoppedProjectWithoutBackend(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, &fakePorts{})

	// Nothing published, nothing running: the expected state and the real one
	// already agree. This is the case a "stopped" flag would have covered.
	state := publishedProject("quiet-app")
	state.LastAddress = ""
	registerContinuityProject(t, state)

	reconcileContinuity()

	assert.Equal(t, 0, client.poolConfigCalls)
	assert.Empty(t, client.transactions)
	assert.Empty(t, client.removals)
}

func TestReconcileKeepsTheBackendWhenDockerCannotBeAsked(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	useFakeContinuity(t, client, &fakePorts{err: errors.New("cannot connect to the Docker daemon")})
	dir := registerContinuityProject(t, publishedProject("docker-down-app"))

	reconcileContinuity()

	// A Docker that cannot answer says nothing about the container: taking a
	// possibly healthy backend out of the pool would cause the outage the
	// integration exists to avoid.
	assert.Empty(t, client.removals)
	assert.Empty(t, client.transactions)
	assert.Equal(t, "http://10.0.0.5:32768", reconciledState(t, dir).LastAddress)
}

func TestReconcileDropsProjectsWithoutState(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())
	continuityProjects.add("deleted-app")

	reconcileContinuity()

	assert.Empty(t, continuityProjects.list())
	assert.Equal(t, 0, client.poolConfigCalls)
}

func TestReconcileUsesTheContainerOfTheDeployedRevision(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{}}
	ports := publishedPorts()
	useFakeContinuity(t, client, ports)

	state := publishedProject("revised-app")
	state.Container = "revised-app-2"
	state.LastAddress = ""
	registerContinuityProject(t, state)

	reconcileContinuity()

	// Docker names the container of a project with revisions after the
	// revision, which the project name alone could never tell.
	assert.Equal(t, []string{"revised-app-2"}, ports.calls)
}

func TestReconcileCarriesOnAfterAFailingProject(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{poolErr: errors.New("connection refused")}
	useFakeContinuity(t, client, publishedPorts())
	registerContinuityProject(t, publishedProject("first-app"))
	registerContinuityProject(t, publishedProject("second-app"))

	reconcileContinuity()

	// One unreachable pool must not stop the pass: every project is tried.
	assert.Equal(t, 2, client.poolConfigCalls)
}

func TestReconciliationRaisesReadyEvenWhenContinuityIsDown(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{poolErr: errors.New("connection refused")}
	useFakeContinuity(t, client, publishedPorts())
	registerContinuityProject(t, publishedProject("unreachable-app"))

	// The ticker must not fire again while the test globals are still in use.
	previousInterval := reconcileInterval
	reconcileInterval = time.Hour
	t.Cleanup(func() { reconcileInterval = previousInterval })

	ready.Store(false)
	t.Cleanup(func() { ready.Store(true) })
	startContinuityReconciliation()

	// A continuity that never answers must not leave the server refusing every
	// request forever.
	assert.Eventually(t, ready.Load, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, client.poolConfigCalls)
}

func TestReconciliationIsReadyWithAnEmptyRegistry(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{}
	useFakeContinuity(t, client, publishedPorts())
	previousInterval := reconcileInterval
	reconcileInterval = time.Hour
	t.Cleanup(func() { reconcileInterval = previousInterval })

	ready.Store(false)
	t.Cleanup(func() { ready.Store(true) })
	startContinuityReconciliation()

	assert.Eventually(t, ready.Load, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 0, client.poolConfigCalls)
}

// TestReconcileAfterAStopKeepsTheProjectRegistered walks the whole stop and
// come back cycle, the reason the state file survives a stop.
func TestReconcileAfterAStopKeepsTheProjectRegistered(t *testing.T) {
	setupTestEnvironment(t)
	client := &fakeContinuityClient{pool: &continuity.Pool{UnconditionalServers: []continuity.ServerHost{
		continuityBackend("cbfca8b3", "http://10.0.0.5:32768"),
	}}}
	ports := &fakePorts{}
	useFakeContinuity(t, client, ports)
	dir := registerContinuityProject(t, publishedProject("cycle-app"))

	// The container is down: the backend goes away, the project stays.
	reconcileContinuity()
	require.Len(t, client.removals, 1)
	assert.Equal(t, []string{"cycle-app"}, continuityProjects.list())

	// The container comes back on a new port: the project is published again
	// without any deploy.
	client.pool = &continuity.Pool{}
	ports.ports = []protocol.Port{{LocalPort: "80", BindPort: "40000", Protocol: "tcp", Address: "0.0.0.0"}}
	reconcileContinuity()

	require.Len(t, client.transactions, 1)
	assert.Equal(t, "http://10.0.0.5:40000", client.transactions[0].address)
	assert.Equal(t, "http://10.0.0.5:40000", reconciledState(t, dir).LastAddress)
}
