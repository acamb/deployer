package continuity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// samplePoolJson reproduces the real output of `continuity pool config POOL
// --json`: capitalized keys, because ServerHostResponse carries no json tag,
// and Address serialized as the exported fields of url.URL instead of a
// string, because *url.URL only implements MarshalBinary.
const samplePoolJson = `{
  "hostname": "my-app.example.com",
  "health_check_interval": 10,
  "health_check_initial_delay": 20,
  "health_check_timeout": 5,
  "health_check_num_ok": 3,
  "health_check_num_fail": 3,
  "conditional_servers": [
    {
      "Id": "3f1a0c9e-0b4d-4f0a-9c1e-9d2f7a5b6c30",
      "Address": {
        "Scheme": "http",
        "Opaque": "",
        "User": null,
        "Host": "10.0.0.6:32770",
        "Path": "",
        "RawPath": "",
        "OmitHost": false,
        "ForceQuery": false,
        "RawQuery": "",
        "Fragment": "",
        "RawFragment": ""
      },
      "Condition": {
        "Header": "X-Canary",
        "Value": "true"
      },
      "ServerStatus": "Healthy",
      "HealthCheckPath": "/health"
    }
  ],
  "unconditional_servers": [
    {
      "Id": "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
      "Address": {
        "Scheme": "http",
        "Opaque": "",
        "User": null,
        "Host": "10.0.0.5:32768",
        "Path": "",
        "RawPath": "",
        "OmitHost": false,
        "ForceQuery": false,
        "RawQuery": "",
        "Fragment": "",
        "RawFragment": ""
      },
      "Condition": {
        "Header": "",
        "Value": ""
      },
      "ServerStatus": "Healthy",
      "HealthCheckPath": "/health"
    },
    {
      "Id": "7b2d6f41-1c58-4a3e-9f77-0d5c2b8e4a92",
      "Address": {
        "Scheme": "https",
        "Opaque": "",
        "User": null,
        "Host": "10.0.0.7:8443",
        "Path": "/api",
        "RawPath": "",
        "OmitHost": false,
        "ForceQuery": false,
        "RawQuery": "",
        "Fragment": "",
        "RawFragment": ""
      },
      "Condition": {
        "Header": "",
        "Value": ""
      },
      "ServerStatus": "Unhealthy",
      "HealthCheckPath": "/api/health"
    }
  ],
  "sticky_sessions": false,
  "sticky_method": "LBCookie",
  "sticky_session_timeout": 0
}`

func samplePool(t *testing.T) *Pool {
	t.Helper()
	var pool Pool
	require.NoError(t, json.Unmarshal([]byte(samplePoolJson), &pool))
	return &pool
}

func TestPoolUnmarshalsContinuityOutput(t *testing.T) {
	pool := samplePool(t)

	assert.Equal(t, "my-app.example.com", pool.Hostname)
	require.Len(t, pool.UnconditionalServers, 2)
	require.Len(t, pool.ConditionalServers, 1)

	first := pool.UnconditionalServers[0]
	assert.Equal(t, "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11", first.Id)
	assert.Equal(t, "http://10.0.0.5:32768", first.Address.String())
	assert.Equal(t, "Healthy", first.ServerStatus)
	assert.Equal(t, "/health", first.HealthCheckPath)

	// The path of the address survives, scheme included.
	assert.Equal(t, "https://10.0.0.7:8443/api", pool.UnconditionalServers[1].Address.String())
	assert.Equal(t, "http://10.0.0.6:32770", pool.ConditionalServers[0].Address.String())
}

func TestPoolServersIncludesBothLists(t *testing.T) {
	pool := samplePool(t)

	servers := pool.Servers()
	require.Len(t, servers, 3)

	ids := make([]string, 0, len(servers))
	for _, server := range servers {
		ids = append(ids, server.Id)
	}
	assert.ElementsMatch(t, []string{
		"cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
		"7b2d6f41-1c58-4a3e-9f77-0d5c2b8e4a92",
		"3f1a0c9e-0b4d-4f0a-9c1e-9d2f7a5b6c30",
	}, ids)
}

func TestPoolServersOnEmptyPool(t *testing.T) {
	pool := &Pool{Hostname: "empty.example.com"}
	assert.Empty(t, pool.Servers())
}

func TestFindByAddress(t *testing.T) {
	pool := samplePool(t)

	testCases := []struct {
		name       string
		address    string
		expectFind bool
		expectId   string
	}{
		{
			name:       "Unconditional backend",
			address:    "http://10.0.0.5:32768",
			expectFind: true,
			expectId:   "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
		},
		{
			name:       "Conditional backend",
			address:    "http://10.0.0.6:32770",
			expectFind: true,
			expectId:   "3f1a0c9e-0b4d-4f0a-9c1e-9d2f7a5b6c30",
		},
		{
			name:       "Backend with a path",
			address:    "https://10.0.0.7:8443/api",
			expectFind: true,
			expectId:   "7b2d6f41-1c58-4a3e-9f77-0d5c2b8e4a92",
		},
		{
			name:       "Trailing slash and uppercase scheme still match",
			address:    "HTTP://10.0.0.5:32768/",
			expectFind: true,
			expectId:   "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
		},
		{
			// The stale address of correction 3: the flag must simply be
			// omitted instead of breaking the whole transaction.
			name:    "Address no longer in the pool",
			address: "http://10.0.0.5:32769",
		},
		{
			name:    "Same host on another scheme is a different backend",
			address: "https://10.0.0.5:32768",
		},
		{
			name:    "Empty address",
			address: "",
		},
		{
			name:    "Blank address",
			address: "   ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server, found := pool.FindByAddress(tc.address)
			if !tc.expectFind {
				assert.False(t, found)
				assert.Empty(t, server.Id)
				return
			}
			require.True(t, found)
			assert.Equal(t, tc.expectId, server.Id)
		})
	}
}

func TestFindByAddressWithDuplicatedAddress(t *testing.T) {
	// A redeploy on the same port with remove_previous disabled leaves two
	// interchangeable backends: either one is a correct answer.
	address := URL{Scheme: "http", Host: "10.0.0.5:32768"}
	pool := &Pool{UnconditionalServers: []ServerHost{
		{Id: "first", Address: address},
		{Id: "second", Address: address},
	}}

	server, found := pool.FindByAddress("http://10.0.0.5:32768")
	require.True(t, found)
	assert.Equal(t, "first", server.Id)
}

func TestFindByAddressOnBackendWithoutAddress(t *testing.T) {
	// `"Address": null` deserializes into the zero URL, which must not match
	// an empty lookup nor a real address.
	pool := &Pool{UnconditionalServers: []ServerHost{{Id: "first"}}}

	_, found := pool.FindByAddress("http://10.0.0.5:32768")
	assert.False(t, found)
	_, found = pool.FindByAddress("")
	assert.False(t, found)
}
