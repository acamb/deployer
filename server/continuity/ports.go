package continuity

import (
	"deployer/protocol"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrNotPublished is wrapped in the error PickPublishedPort returns when the
// container publishes no such port. The reconciliation tells this case apart
// from a Docker failure with errors.Is: a container publishing nothing is a
// container that is down, and its backend has to be removed, while a Docker
// that cannot be asked says nothing about the container and must be left alone.
var ErrNotPublished = errors.New("not published")

// PickPublishedPort returns the host port on which internalPort is published.
//
// It expects the output of `docker port <container>` invoked *without* a port
// argument: with a port argument Docker prints a bare `0.0.0.0:32768` line,
// without the `->` separator that parsePortsOutput requires, so the filtering
// has to happen here rather than by letting Docker do it.
//
// Only tcp publications are considered, and an IPv4 binding is preferred over
// an IPv6 one: the address is handed to Continuity as the host part of an URL,
// where a bare `::` would be useless.
func PickPublishedPort(ports []protocol.Port, internalPort string) (string, error) {
	internalPort = strings.TrimSpace(internalPort)
	if internalPort == "" {
		return "", errors.New("no internal port configured for the project")
	}
	fallback := ""
	for _, port := range ports {
		if strings.TrimSpace(port.LocalPort) != internalPort {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(port.Protocol), "tcp") {
			continue
		}
		bindPort := strings.TrimSpace(port.BindPort)
		if bindPort == "" {
			continue
		}
		if isIPv4(port.Address) {
			return bindPort, nil
		}
		if fallback == "" {
			fallback = bindPort
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("container port %s/tcp is %w", internalPort, ErrNotPublished)
}

func isIPv4(address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	return ip != nil && ip.To4() != nil
}
