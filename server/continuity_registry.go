package main

import (
	"deployer/server/continuity"
	"log"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
)

// ready gates every incoming request. It stays false until the server knows
// what is published on Continuity for the projects it hosts: answering a deploy
// before that would race with the initial reconciliation, which could remove
// the backend just published. Requests received meanwhile are bounced back with
// protocol.NotReady, a status the client turns into "retry in a few seconds".
var ready atomic.Bool

// continuityProjects is the in-memory registry of the projects with the
// Continuity integration enabled: the projects the server has to keep published
// on the load balancer. There is no database and no central index file, so it is
// rebuilt at startup by scanning the working directory and it grows as deploys
// register new projects.
var continuityProjects = newProjectRegistry()

// projectRegistry is a set of project names. The mutex is not optional:
// concurrent deploys add to it while the reconciliation pass walks it.
type projectRegistry struct {
	mutex sync.Mutex
	names map[string]struct{}
}

func newProjectRegistry() *projectRegistry {
	return &projectRegistry{names: make(map[string]struct{})}
}

// add records a project as one to keep published. Registering an already known
// project is a no-op.
func (r *projectRegistry) add(project string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.names[project] = struct{}{}
}

// list returns a snapshot of the registered projects, sorted so that logs and
// reconciliation passes have a stable order.
func (r *projectRegistry) list() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	projects := make([]string, 0, len(r.names))
	for project := range r.names {
		projects = append(projects, project)
	}
	sort.Strings(projects)
	return projects
}

// replace swaps the whole content of the registry, as the startup scan does.
func (r *projectRegistry) replace(projects []string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.names = make(map[string]struct{}, len(projects))
	for _, project := range projects {
		r.names[project] = struct{}{}
	}
}

// scanContinuityProjects returns the projects that have a Continuity state
// under workingDirectory.
//
// The glob goes exactly one level deep, which is right because the state lives
// at the project level and never under a revision: a project is a single
// backend, whatever revision is currently deployed.
func scanContinuityProjects(workingDirectory string) []string {
	pattern := filepath.Join(workingDirectory, "*", continuity.DirName, continuity.StateFileName)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("Continuity: cannot scan %s looking for registered projects: %v", workingDirectory, err)
		return nil
	}
	projects := make([]string, 0, len(matches))
	for _, match := range matches {
		directory := filepath.Dir(match)
		project := filepath.Base(filepath.Dir(directory))
		if _, err := continuity.LoadState(directory); err != nil {
			// A truncated or hand edited state.json must not keep the server
			// from starting: the project is left out of the registry and the
			// next deploy rewrites its state.
			log.Printf("Continuity: ignoring the state of %s: %v", project, err)
			continue
		}
		projects = append(projects, project)
	}
	sort.Strings(projects)
	return projects
}

// loadContinuityRegistry rebuilds the registry from the working directory, as
// done at startup.
func loadContinuityRegistry(workingDirectory string) {
	projects := scanContinuityProjects(workingDirectory)
	continuityProjects.replace(projects)
	if len(projects) == 0 {
		log.Printf("Continuity: no project registered under %s", workingDirectory)
		return
	}
	log.Printf("Continuity: %d registered project(s): %v", len(projects), projects)
}
