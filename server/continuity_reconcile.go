package main

import (
	"context"
	"deployer/server/continuity"
	"errors"
	"log"
	"time"
)

// reconcileInterval is how often the published backends are compared with
// reality. A minute is short enough to repair a container that came back on a
// different ephemeral port before anybody notices, and long enough not to
// hammer Continuity with a pool config per project.
var reconcileInterval = time.Minute

// startContinuityReconciliation runs the reconciliation loop in the background,
// starting with a pass executed right away.
//
// The ready flag is raised as soon as that first pass is over, whatever it
// found: a Continuity that is unreachable, or a pool config that keeps failing,
// must not keep the server from serving. Every CLI call is bounded by the
// timeout of continuity.CLI, so the first pass cannot hang forever either.
func startContinuityReconciliation() {
	go func() {
		reconcileContinuity()
		ready.Store(true)
		log.Printf("Continuity: initial reconciliation completed, the server is ready")

		ticker := time.NewTicker(reconcileInterval)
		defer ticker.Stop()
		for range ticker.C {
			reconcileContinuity()
		}
	}()
}

// reconcileContinuity brings every registered project back in line with what is
// published on Continuity. Containers and ports change without any deploy
// (restart policies, a reboot of the host, a backend removed by hand), so the
// published state is compared with the real one instead of being assumed.
func reconcileContinuity() {
	defer func() {
		// A pass must never take the server down, nor leave it stuck at not
		// ready because of a panic on a single project.
		if problem := recover(); problem != nil {
			log.Printf("Continuity: the reconciliation pass panicked: %v", problem)
		}
	}()
	projects := continuityProjects.list()
	if len(projects) == 0 {
		return
	}
	client := newContinuityClient()
	for _, project := range projects {
		if err := reconcileProject(client, project); err != nil {
			log.Printf("Continuity: cannot reconcile %s: %v", project, err)
		}
	}
}

// reconcileProject compares the real state of one project (the port its
// container publishes right now) with the configured one (the backends of its
// pool) and repairs the difference.
//
// Only the backend at the expected address and the one at LastAddress are ever
// touched: a pool is a hostname and may legitimately hold backends of other
// deployer servers, conditional backends or backends added by hand, and
// Continuity offers no field telling them apart from ours.
func reconcileProject(client continuityClient, project string) error {
	dir := continuity.Dir(config.WorkingDirectory, project)
	state, err := continuity.LoadState(dir)
	if err != nil {
		return err
	}
	if state == nil {
		// The project was removed along with its files: nothing left to keep
		// published, and nothing left to read at the next pass either.
		continuityProjects.remove(project)
		log.Printf("Continuity: %s has no state any more, it leaves the registry", project)
		return nil
	}

	address, err := backendAddress(state, state.ContainerName())
	if err != nil {
		if !errors.Is(err, continuity.ErrNotPublished) {
			// Docker could not be asked at all: that says nothing about the
			// container, so the backend is left exactly where it is. Removing
			// it on a Docker hiccup would take a healthy project out of the
			// load balancer.
			if state.LastAddress == "" {
				return nil
			}
			return err
		}
		// The container publishes nothing: it is down, and no backend is
		// expected for the project. This is what makes a "stopped" flag
		// unnecessary — and why nothing is published again here.
		if state.LastAddress == "" {
			return nil
		}
		log.Printf("Continuity: %s no longer publishes port %s, its backend %s is removed",
			project, state.InternalPort, state.LastAddress)
		return removeBackend(client, dir, state)
	}

	cfgPath, err := projectConfigPath(dir, project)
	if err != nil {
		return err
	}
	pool, err := client.PoolConfig(context.Background(), cfgPath, state.Pool)
	if err != nil {
		return err
	}
	_, published := pool.FindByAddress(address)
	if published && state.LastAddress == address {
		return nil
	}
	if state.LastAddress == address {
		log.Printf("Continuity: the backend of %s (%s) is gone from pool %s, publishing it again",
			project, address, state.Pool)
	} else if state.LastAddress == "" {
		log.Printf("Continuity: %s is up again, publishing it at %s", project, address)
	} else {
		log.Printf("Continuity: %s moved from %s to %s, publishing the new address",
			project, state.LastAddress, address)
	}
	// The pool just read is handed over on purpose: the UUID to remove has to
	// be resolved from the configuration taken *before* the transaction, or the
	// backend the transaction is about to create could be the one removed.
	return publishBackendInPool(client, dir, cfgPath, state, address, pool)
}
