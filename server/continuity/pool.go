package continuity

import (
	"net/url"
	"strings"
)

// Pool mirrors the JSON printed by `continuity pool config POOL --json`.
//
// Only the entries needed to resolve a backend are declared: the health check
// tuning of the pool is owned by whoever created it, not by deployer.
type Pool struct {
	Hostname             string       `json:"hostname"`
	ConditionalServers   []ServerHost `json:"conditional_servers"`
	UnconditionalServers []ServerHost `json:"unconditional_servers"`
}

// ServerHost is a backend registered in a pool.
//
// The field names are capitalized on purpose: continuity serializes
// ServerHostResponse without any json tag, so the keys of the marshalled
// object are the Go field names.
type ServerHost struct {
	Id              string `json:"Id"`
	Address         URL    `json:"Address"`
	ServerStatus    string `json:"ServerStatus"`
	HealthCheckPath string `json:"HealthCheckPath"`
}

// URL is the address of a backend as continuity serializes it.
//
// Continuity holds it in a *url.URL, which only implements MarshalBinary --
// ignored by encoding/json -- so the address travels as a nested object with
// the exported fields of url.URL, not as a string. Only the three fields that
// make up a backend address are declared here.
type URL struct {
	Scheme string `json:"Scheme"`
	Host   string `json:"Host"`
	Path   string `json:"Path"`
}

// String rebuilds the address in the `scheme://host[path]` form used
// everywhere else in deployer, in the State and on the command line.
func (u URL) String() string {
	address := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return address.String()
}

// Servers returns every backend of the pool, conditional ones included: a
// backend registered by deployer is unconditional, but a stale one could have
// been moved by hand and must still be resolvable.
func (p *Pool) Servers() []ServerHost {
	servers := make([]ServerHost, 0, len(p.UnconditionalServers)+len(p.ConditionalServers))
	servers = append(servers, p.UnconditionalServers...)
	servers = append(servers, p.ConditionalServers...)
	return servers
}

// FindByAddress resolves an address to the backend published at it. It is the
// only way to identify a backend to remove, since continuity assigns the UUIDs
// itself and never exposes them outside of `pool config`.
//
// When several backends share the same address -- a redeploy on the same port
// without remove_previous -- the first one is returned: they are functionally
// interchangeable, so removing either of them is correct.
func (p *Pool) FindByAddress(address string) (ServerHost, bool) {
	wanted := normalizeAddress(address)
	if wanted == "" {
		return ServerHost{}, false
	}
	for _, server := range p.Servers() {
		if normalizeAddress(server.Address.String()) == wanted {
			return server, true
		}
	}
	return ServerHost{}, false
}

// normalizeAddress makes two addresses comparable regardless of the casing of
// the scheme and of a trailing slash, which continuity may or may not keep.
func normalizeAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return strings.TrimSuffix(strings.ToLower(address), "/")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	return parsed.String()
}
