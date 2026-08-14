package main

import (
	"context"
	"deployer/protocol"
	"deployer/server/continuity"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// continuityClient is the subset of the Continuity CLI used by the glue. It
// exists so that the deploy flow can be exercised without the binary and
// without a Continuity server.
type continuityClient interface {
	Transaction(ctx context.Context, cfgPath, pool, address, healthCheck, removeUUID string) error
	AddServer(ctx context.Context, cfgPath, pool, address, healthCheck string) error
	PoolConfig(ctx context.Context, cfgPath, pool string) (*continuity.Pool, error)
	RemoveServer(ctx context.Context, cfgPath, pool, uuid string) error
}

// newContinuityClient builds the client used by the glue, and
// continuityPortsBinding resolves the ports published by a container. Both are
// variables so that the tests can replace them.
var newContinuityClient = func() continuityClient {
	bin := ""
	if config != nil {
		bin = config.ContinuityBin
	}
	return continuity.NewCLI(bin)
}

var continuityPortsBinding = getPortsBinding

// registerBackend publishes the container just started as a backend of the
// Continuity pool of the project, replacing the previously published one.
//
// It is a no-op for the requests that do not carry the Continuity fields. The
// returned error tells whether the publication succeeded; deciding whether it
// is fatal to the deploy (and whether the new revision must be rolled back) is
// the job of finalizeBackend.
func registerBackend(request protocol.Request) error {
	if !request.ContinuityEnable {
		return nil
	}
	err := registerBackendOn(newContinuityClient(), request)
	if err != nil {
		log.Printf("Continuity: cannot publish %s: %v", request.Name, err)
	}
	return err
}

// teardownContainer stops the container of a request. It is a variable so that
// the rollback of a failed publication can be exercised without Docker, like
// newContinuityClient and continuityPortsBinding.
var teardownContainer = stopContainer

// backendResult is the outcome of finalizeBackend: how a deploy, start or
// restart must end once the attempt to add the container to the load balancer
// is over.
type backendResult struct {
	// err is nil when the container was added to the load balancer; otherwise
	// the deploy failed and must be reported as such.
	err error
	// rolledBack is true when the new revision was torn down and the previous
	// one kept live, false when the container was left running for the
	// reconciliation to retry (no previous revision to fall back to).
	rolledBack bool
	// keptRevision is the container name of the revision left active after a
	// rollback, used only to tell the user which one is still serving.
	keptRevision string
}

// finalizeBackend publishes the container on Continuity and, when the
// publication fails while a distinct previous revision is still serving, tears
// the new revision down and restores the previous state, so the load balancer
// keeps routing to the revision that is still healthy.
//
// Adding the container to the load balancer is part of the definition of a
// successful deploy: unlike a bare registerBackend, a failure here is fatal.
func finalizeBackend(request protocol.Request) backendResult {
	if !request.ContinuityEnable {
		return backendResult{}
	}
	dir := continuity.Dir(config.WorkingDirectory, request.Name)
	// The snapshot is taken before the publication overwrites the state with the
	// parameters of this deploy: it is what the reconciliation must see again if
	// the new revision has to be rolled back.
	previous, _ := continuity.LoadState(dir)

	err := registerBackend(request)
	if err == nil {
		return backendResult{}
	}

	// A rollback is only safe when a *distinct* previous revision is still up and
	// still published: its container is a different one, so terminating the new
	// revision does not take the service down, and the continuity transaction is
	// atomic, so a rolled back transaction left the previous backend healthy.
	newContainer := containerName(request.Name, request.Revision)
	if previous == nil || previous.LastAddress == "" || previous.ContainerName() == newContainer {
		return backendResult{err: err}
	}

	// Restore the previous state, or the next reconciliation pass would see the
	// new, now dead, container publish nothing and drop the previous backend.
	if restoreErr := continuity.SaveState(dir, previous); restoreErr != nil {
		log.Printf("Continuity: cannot restore the state of %s after a failed publication: %v", request.Name, restoreErr)
	}
	if teardownErr := teardownContainer(request); teardownErr != nil {
		log.Printf("Continuity: cannot stop the rolled back revision of %s: %v", request.Name, teardownErr)
	}
	log.Printf("Continuity: publication of %s failed, revision %s kept active: %v", request.Name, previous.ContainerName(), err)
	return backendResult{err: err, rolledBack: true, keptRevision: previous.ContainerName()}
}

// continuityFailureMessage is the Ko message for a deploy, start or restart
// whose container came up but could not be added to the load balancer.
func continuityFailureMessage(result backendResult) string {
	if result.rolledBack {
		return fmt.Sprintf("Load balancer registration failed: %v. Revision %s is still active, the new one was rolled back", result.err, result.keptRevision)
	}
	return fmt.Sprintf("Load balancer registration failed: %v. The container is running but not on the load balancer yet, it will be retried", result.err)
}

func registerBackendOn(client continuityClient, request protocol.Request) error {
	dir := continuity.Dir(config.WorkingDirectory, request.Name)
	cfgPath, err := continuity.WriteProjectConfig(dir, request.ContinuityConfig, request.ContinuityPrivateKey)
	if err != nil {
		return err
	}
	// The deploy parameters are persisted before anything else: they only
	// travel with this request and every reconciliation pass needs them, even
	// if the registration below fails or the server restarts right after.
	state, err := continuity.UpdateDeployParams(dir, continuity.State{
		Project:         request.Name,
		Container:       containerName(request.Name, request.Revision),
		Pool:            request.ContinuityPool,
		HealthCheckPath: request.ContinuityHealthCheckPath,
		InternalPort:    request.ContinuityInternalPort,
		RemovePrevious:  request.ContinuityRemovePrevious,
		AdvertiseBase:   request.ContinuityAdvertiseBase,
	})
	if err != nil {
		return err
	}
	// From now on the project is one the reconciliation has to look after, even
	// if the publication below fails: its state is on disk and the next startup
	// scan would pick it up anyway.
	continuityProjects.add(request.Name)
	address, err := backendAddress(state, state.ContainerName())
	if err != nil {
		return err
	}
	return publishBackend(client, dir, cfgPath, state, address)
}

// publishBackend runs the transaction adding address as a backend of the pool
// and, when possible, removing the backend previously published for the
// project.
func publishBackend(client continuityClient, dir, cfgPath string, state *continuity.State, address string) error {
	// A single pool config, taken *before* the transaction: the UUID of the
	// previous backend is never stored, it is resolved from its address. A
	// stored UUID gone stale would make the whole call fail before the new
	// backend is added, and resolving it after the transaction could match the
	// backend just created when the address did not change.
	pool, err := client.PoolConfig(context.Background(), cfgPath, state.Pool)
	if err != nil {
		return err
	}
	return publishBackendInPool(client, dir, cfgPath, state, address, pool)
}

// publishBackendInPool is publishBackend once the configuration of the pool is
// known. The reconciliation reads that configuration to decide whether a repair
// is needed at all, and hands it over instead of asking for it a second time.
func publishBackendInPool(client continuityClient, dir, cfgPath string, state *continuity.State, address string, pool *continuity.Pool) error {
	removeUUID := ""
	if state.RemovePrevious && state.LastAddress != "" {
		if previous, found := pool.FindByAddress(state.LastAddress); found {
			removeUUID = previous.Id
		} else {
			// Removed by hand, or never registered: the flag is simply
			// omitted, an unknown UUID would break the whole transaction.
			log.Printf("Continuity: the previous backend of %s (%s) is no longer in pool %s, it will not be removed",
				state.Project, state.LastAddress, state.Pool)
		}
	}
	// With a previous backend to remove, a transaction adds the new backend and
	// drops the old one only once the new one is healthy (zero downtime). With
	// nothing to remove -- the first deploy, or a previous backend already gone
	// -- a plain add is used instead: `server transaction` requires a valid,
	// existing --remove-server UUID and would fail against an (for this project)
	// empty pool.
	if removeUUID != "" {
		if err := client.Transaction(context.Background(), cfgPath, state.Pool, address, state.HealthCheckPath, removeUUID); err != nil {
			return err
		}
		log.Printf("Continuity: %s published at %s, previous backend %s removed", state.Project, address, removeUUID)
	} else {
		if err := client.AddServer(context.Background(), cfgPath, state.Pool, address, state.HealthCheckPath); err != nil {
			return err
		}
		log.Printf("Continuity: %s published at %s", state.Project, address)
	}
	state.LastAddress = address
	return continuity.SaveState(dir, state)
}

// deregisterBackend removes from its pool the backend published for a project.
//
// It is invoked when a container is stopped, *before* stopping it, because a
// stop with DeleteFiles wipes the working directory of the project, the
// Continuity state included. The state file itself is kept, with LastAddress
// cleared: the project stays in the registry, so a container coming back up on
// its own is published again by the reconciliation.
func deregisterBackend(project string) error {
	err := deregisterBackendOn(newContinuityClient(), project)
	if err != nil {
		log.Printf("Continuity: cannot remove the backend of %s: %v", project, err)
	}
	return err
}

func deregisterBackendOn(client continuityClient, project string) error {
	dir := continuity.Dir(config.WorkingDirectory, project)
	state, err := continuity.LoadState(dir)
	if err != nil {
		return err
	}
	if state == nil || state.LastAddress == "" {
		// Either the project has no Continuity integration, or nothing is
		// published for it: there is nothing to remove.
		return nil
	}
	return removeBackend(client, dir, state)
}

// removeBackend removes the backend currently published for the project and
// clears LastAddress. It is shared with the periodic reconciliation.
func removeBackend(client continuityClient, dir string, state *continuity.State) error {
	cfgPath, err := projectConfigPath(dir, state.Project)
	if err != nil {
		return err
	}
	pool, err := client.PoolConfig(context.Background(), cfgPath, state.Pool)
	if err != nil {
		return err
	}
	if backend, found := pool.FindByAddress(state.LastAddress); found {
		if err := client.RemoveServer(context.Background(), cfgPath, state.Pool, backend.Id); err != nil {
			// LastAddress is left untouched so that the next reconciliation
			// pass retries instead of forgetting a live backend.
			return err
		}
		log.Printf("Continuity: %s removed from pool %s (%s)", state.Project, state.Pool, state.LastAddress)
	} else {
		// Already gone: nothing to do, but the state must still be cleared.
		log.Printf("Continuity: the backend of %s (%s) was already absent from pool %s",
			state.Project, state.LastAddress, state.Pool)
	}
	state.LastAddress = ""
	return continuity.SaveState(dir, state)
}

// lbStatus returns the configuration of the Continuity pool a project is
// published on, essentially the output of `continuity pool config`. It relies
// on the state persisted at deploy time, so a project that was never deployed
// with the integration enabled has no pool to look at.
func lbStatus(project string) (protocol.LbStatusResponse, error) {
	return lbStatusOn(newContinuityClient(), project)
}

func lbStatusOn(client continuityClient, project string) (protocol.LbStatusResponse, error) {
	dir := continuity.Dir(config.WorkingDirectory, project)
	state, err := continuity.LoadState(dir)
	if err != nil {
		return protocol.LbStatusResponse{}, err
	}
	if state == nil {
		return protocol.LbStatusResponse{}, errors.New("continuity is not configured for project " + project + ": deploy it with the integration enabled first")
	}
	cfgPath, err := projectConfigPath(dir, project)
	if err != nil {
		return protocol.LbStatusResponse{}, err
	}
	pool, err := client.PoolConfig(context.Background(), cfgPath, state.Pool)
	if err != nil {
		return protocol.LbStatusResponse{}, err
	}
	return poolStatus(pool), nil
}

// poolStatus maps a continuity.Pool onto the wire payload, flagging conditional
// backends so the client can tell them apart from the ones deployer publishes.
func poolStatus(pool *continuity.Pool) protocol.LbStatusResponse {
	response := protocol.LbStatusResponse{Hostname: pool.Hostname}
	appendBackends := func(servers []continuity.ServerHost, conditional bool) {
		for _, server := range servers {
			response.Backends = append(response.Backends, protocol.LbBackend{
				Address:         server.Address.String(),
				Status:          server.ServerStatus,
				HealthCheckPath: server.HealthCheckPath,
				Conditional:     conditional,
			})
		}
	}
	appendBackends(pool.UnconditionalServers, false)
	appendBackends(pool.ConditionalServers, true)
	return response
}

// projectConfigPath returns the path of the continuity configuration written
// for a project, checking that it is still there: without it no CLI call can be
// made, and the reason has to reach the logs.
func projectConfigPath(dir, project string) (string, error) {
	cfgPath := filepath.Join(dir, continuity.ConfigFileName)
	if _, err := os.Stat(cfgPath); err != nil {
		return "", errors.New("cannot read the continuity configuration of " + project + ": " + err.Error())
	}
	return cfgPath, nil
}

// backendAddress computes the address under which the container is reachable
// by Continuity: the advertise base followed by the host port on which the
// internal port of the container is published.
func backendAddress(state *continuity.State, container string) (string, error) {
	// `docker port` is invoked without a port argument on purpose: with one it
	// prints a bare `0.0.0.0:32768`, which parsePortsOutput cannot parse.
	ports, err := continuityPortsBinding(container, "")
	if err != nil {
		return "", err
	}
	port, err := continuity.PickPublishedPort(ports, state.InternalPort)
	if err != nil {
		return "", err
	}
	base, err := resolveAdvertiseBase(state.AdvertiseBase)
	if err != nil {
		return "", err
	}
	return base + ":" + port, nil
}

// resolveAdvertiseBase returns the base URL to publish, scheme included: the
// per-project override wins over the server configuration, which wins over the
// hostname of the server. ListenAddress is deliberately not a candidate: it is
// 0.0.0.0 by default, useless as the address of a backend.
func resolveAdvertiseBase(override string) (string, error) {
	if base := strings.TrimSpace(override); base != "" {
		return strings.TrimSuffix(base, "/"), nil
	}
	if config != nil {
		if base := strings.TrimSpace(config.ContinuityAdvertiseBase); base != "" {
			return strings.TrimSuffix(base, "/"), nil
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", errors.New("cannot resolve the continuity advertise base: " + err.Error())
	}
	if strings.TrimSpace(hostname) == "" {
		return "", errors.New("cannot resolve the continuity advertise base: the hostname is empty")
	}
	return "http://" + hostname, nil
}

// containerName returns the name Docker gave the container, which carries the
// revision as a suffix when the project uses revisions.
func containerName(name, revision string) string {
	if revision != "" {
		return name + "-" + revision
	}
	return name
}

// continuityWarning appends the Continuity problem to an otherwise successful
// message: the container is up, the deploy succeeded, only the load balancer
// registration did not.
func continuityWarning(message string, err error) string {
	if err == nil {
		return message
	}
	return message + " (continuity warning: " + err.Error() + ")"
}
