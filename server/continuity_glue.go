package main

import (
	"context"
	"deployer/protocol"
	"deployer/server/continuity"
	"errors"
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
// returned error is never fatal for the caller: at this point Docker has
// already started the container, so the deploy succeeded and the problem is
// reported as a warning attached to the successful response.
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
		Pool:            request.ContinuityPool,
		HealthCheckPath: request.ContinuityHealthCheckPath,
		InternalPort:    request.ContinuityInternalPort,
		RemovePrevious:  request.ContinuityRemovePrevious,
		AdvertiseBase:   request.ContinuityAdvertiseBase,
	})
	if err != nil {
		return err
	}
	address, err := backendAddress(state, containerName(request.Name, request.Revision))
	if err != nil {
		return err
	}
	return publishBackend(client, dir, cfgPath, state, address)
}

// publishBackend runs the transaction adding address as a backend of the pool
// and, when possible, removing the backend previously published for the
// project. It is shared with the periodic reconciliation.
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
	if err := client.Transaction(context.Background(), cfgPath, state.Pool, address, state.HealthCheckPath, removeUUID); err != nil {
		return err
	}
	if removeUUID != "" {
		log.Printf("Continuity: %s published at %s, previous backend %s removed", state.Project, address, removeUUID)
	} else {
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
	cfgPath := filepath.Join(dir, continuity.ConfigFileName)
	if _, err := os.Stat(cfgPath); err != nil {
		return errors.New("cannot read the continuity configuration of " + state.Project + ": " + err.Error())
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
