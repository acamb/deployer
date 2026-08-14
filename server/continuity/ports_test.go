package continuity

import (
	"deployer/protocol"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPickPublishedPort(t *testing.T) {
	testCases := []struct {
		name         string
		ports        []protocol.Port
		internalPort string
		expectError  bool
		errorMessage string
		expectPort   string
	}{
		{
			name: "Single tcp publication",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectPort:   "32768",
		},
		{
			name: "Other container ports are ignored",
			ports: []protocol.Port{
				{LocalPort: "443", BindPort: "32769", Protocol: "tcp", Address: "0.0.0.0"},
				{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectPort:   "32768",
		},
		{
			name: "IPv4 preferred over IPv6",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "32769", Protocol: "tcp", Address: "::"},
				{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectPort:   "32768",
		},
		{
			name: "IPv6 only publication is still usable",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "32769", Protocol: "tcp", Address: "::"},
			},
			internalPort: "80",
			expectPort:   "32769",
		},
		{
			name: "UDP publication is not a backend",
			ports: []protocol.Port{
				{LocalPort: "53", BindPort: "5353", Protocol: "udp", Address: "0.0.0.0"},
			},
			internalPort: "53",
			expectError:  true,
			errorMessage: "53/tcp is not published",
		},
		{
			name: "Same port published on tcp and udp",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "5353", Protocol: "udp", Address: "0.0.0.0"},
				{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectPort:   "32768",
		},
		{
			name: "Container port not published",
			ports: []protocol.Port{
				{LocalPort: "443", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectError:  true,
			errorMessage: "80/tcp is not published",
		},
		{
			name:         "No published port at all",
			ports:        nil,
			internalPort: "80",
			expectError:  true,
			errorMessage: "80/tcp is not published",
		},
		{
			name: "Missing internal port",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "",
			expectError:  true,
			errorMessage: "no internal port configured",
		},
		{
			name: "Publication without host port is skipped",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "", Protocol: "tcp", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectError:  true,
			errorMessage: "80/tcp is not published",
		},
		{
			name: "Uppercase protocol",
			ports: []protocol.Port{
				{LocalPort: "80", BindPort: "32768", Protocol: "TCP", Address: "0.0.0.0"},
			},
			internalPort: "80",
			expectPort:   "32768",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			port, err := PickPublishedPort(tc.ports, tc.internalPort)
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMessage)
				assert.Empty(t, port)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectPort, port)
		})
	}
}

func TestPickPublishedPortReportsADownContainer(t *testing.T) {
	// The reconciliation tells a container publishing nothing apart from a
	// Docker that could not be asked, and only the first one costs a backend.
	_, err := PickPublishedPort([]protocol.Port{
		{LocalPort: "443", BindPort: "32768", Protocol: "tcp", Address: "0.0.0.0"},
	}, "80")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotPublished))

	// A project without an internal port is a configuration problem, not a
	// container that is down.
	_, err = PickPublishedPort(nil, "")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotPublished))
}
