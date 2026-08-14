package continuity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConfigPath = "/opt/deployer/myapp/.continuity/config.yaml"

// recordedCall is one invocation captured by fakeRunner.
type recordedCall struct {
	bin  string
	args []string
}

// fakeRunner replaces the exec of the continuity CLI, so that every test in
// this file runs without the binary and without a continuity server.
type fakeRunner struct {
	calls  []recordedCall
	stdout string
	stderr string
	err    error
	// deadline makes the runner behave like a command killed by its context.
	deadline bool
	// gotDeadline records whether the CLI bounded the invocation.
	gotDeadline bool
}

func (f *fakeRunner) run(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	_, f.gotDeadline = ctx.Deadline()
	f.calls = append(f.calls, recordedCall{bin: bin, args: args})
	if f.deadline {
		return nil, nil, context.DeadlineExceeded
	}
	return []byte(f.stdout), []byte(f.stderr), f.err
}

func newTestCLI(runner *fakeRunner) *CLI {
	return &CLI{Bin: "continuity", Timeout: time.Second, run: runner.run}
}

func TestBuildTransactionArgs(t *testing.T) {
	testCases := []struct {
		name        string
		pool        string
		healthCheck string
		removeUUID  string
		expected    []string
	}{
		{
			name:        "Every parameter provided",
			pool:        "my-app.example.com",
			healthCheck: "/healthz",
			removeUUID:  "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
			expected: []string{"-f", testConfigPath, "server", "transaction",
				"--pool", "my-app.example.com",
				"--address", "http://10.0.0.5:32768",
				"--health-check", "/healthz",
				"--remove-server", "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11"},
		},
		{
			// No pool: continuity falls back to the default_pool of its
			// configuration.
			name:        "Without pool",
			healthCheck: "/healthz",
			removeUUID:  "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
			expected: []string{"-f", testConfigPath, "server", "transaction",
				"--address", "http://10.0.0.5:32768",
				"--health-check", "/healthz",
				"--remove-server", "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11"},
		},
		{
			// No health check path: continuity falls back to /health.
			name:       "Without health check",
			pool:       "my-app.example.com",
			removeUUID: "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11",
			expected: []string{"-f", testConfigPath, "server", "transaction",
				"--pool", "my-app.example.com",
				"--address", "http://10.0.0.5:32768",
				"--remove-server", "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11"},
		},
		{
			// The first deploy of a project, and the redeploy whose previous
			// address is no longer in the pool: an unknown UUID would make the
			// whole call fail before the new backend is added.
			name:        "Without previous backend",
			pool:        "my-app.example.com",
			healthCheck: "/healthz",
			expected: []string{"-f", testConfigPath, "server", "transaction",
				"--pool", "my-app.example.com",
				"--address", "http://10.0.0.5:32768",
				"--health-check", "/healthz"},
		},
		{
			name: "Only the mandatory parameters",
			expected: []string{"-f", testConfigPath, "server", "transaction",
				"--address", "http://10.0.0.5:32768"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildTransactionArgs(testConfigPath, tc.pool, "http://10.0.0.5:32768", tc.healthCheck, tc.removeUUID)
			assert.Equal(t, tc.expected, args)
		})
	}
}

func TestBuildServerAddArgs(t *testing.T) {
	// Every optional flag provided.
	assert.Equal(t,
		[]string{"-f", testConfigPath, "server", "add",
			"--pool", "my-app.example.com",
			"--address", "http://10.0.0.5:32768",
			"--health-check", "/healthz"},
		buildServerAddArgs(testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/healthz"))

	// No pool and no health check: continuity falls back to default_pool and
	// /health. There is never a --remove-server, `server add` removes nothing.
	assert.Equal(t,
		[]string{"-f", testConfigPath, "server", "add", "--address", "http://10.0.0.5:32768"},
		buildServerAddArgs(testConfigPath, "", "http://10.0.0.5:32768", ""))
}

func TestBuildPoolConfigArgs(t *testing.T) {
	// The pool is a positional argument of `pool config`, not a flag.
	assert.Equal(t,
		[]string{"-f", testConfigPath, "pool", "config", "my-app.example.com", "--json"},
		buildPoolConfigArgs(testConfigPath, "my-app.example.com"))

	assert.Equal(t,
		[]string{"-f", testConfigPath, "pool", "config", "--json"},
		buildPoolConfigArgs(testConfigPath, ""))
}

func TestBuildServerDelArgs(t *testing.T) {
	// The subcommand is `del`, not `remove`.
	assert.Equal(t,
		[]string{"-f", testConfigPath, "server", "del", "--pool", "my-app.example.com", "--server", "cbfca8b3"},
		buildServerDelArgs(testConfigPath, "my-app.example.com", "cbfca8b3"))

	assert.Equal(t,
		[]string{"-f", testConfigPath, "server", "del", "--server", "cbfca8b3"},
		buildServerDelArgs(testConfigPath, "", "cbfca8b3"))
}

func TestTransactionSuccess(t *testing.T) {
	runner := &fakeRunner{stderr: "2026/08/13 10:00:00 Transaction 42 in progress...\n" +
		"2026/08/13 10:00:12 Transaction 42 completed successfully\n"}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/health", "")
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, "continuity", runner.calls[0].bin)
	assert.Equal(t, buildTransactionArgs(testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/health", ""), runner.calls[0].args)
	// Every invocation is bounded: the CLI has no timeout of its own.
	assert.True(t, runner.gotDeadline)
}

func TestTransactionRolledBackWithExitCodeZero(t *testing.T) {
	// The CLI logs the rollback and exits 0: without inspecting stderr the
	// failed transaction would be reported as a successful deploy.
	runner := &fakeRunner{stderr: "2026/08/13 10:00:00 Transaction 42 in progress...\n" +
		"2026/08/13 10:00:51 Transaction 42 completed with error: new server is not healthy\n"}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/health", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rolled back")
	assert.Contains(t, err.Error(), "new server is not healthy")
}

func TestTransactionRolledBackWithoutReason(t *testing.T) {
	runner := &fakeRunner{stderr: "Transaction 42 completed with error: \n"}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "", "http://10.0.0.5:32768", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no reason reported")
}

func TestTransactionCommandFailure(t *testing.T) {
	runner := &fakeRunner{
		stdout: "some standard output",
		stderr: "server <uuid> not found in pool",
		err:    errors.New("exit status 1"),
	}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "", "cbfca8b3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "server <uuid> not found in pool")
	assert.Contains(t, err.Error(), "some standard output")
}

func TestTransactionTimeout(t *testing.T) {
	// The CLI polls a pending transaction once a second, forever: an
	// unreachable continuity must not hold the deploy hostage.
	runner := &fakeRunner{deadline: true}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not complete within 1s")
}

func TestTransactionRequiresAddress(t *testing.T) {
	runner := &fakeRunner{}
	cli := newTestCLI(runner)

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "  ", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no address")
	assert.Empty(t, runner.calls)
}

func TestAddServerSuccess(t *testing.T) {
	// `server add` reports success on stderr and exits 0; unlike a transaction
	// there is no rollback to detect.
	runner := &fakeRunner{stderr: "Server added successfully to pool my-app.example.com\n"}
	cli := newTestCLI(runner)

	err := cli.AddServer(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/health")
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, buildServerAddArgs(testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "/health"), runner.calls[0].args)
	assert.True(t, runner.gotDeadline)
}

func TestAddServerCommandFailure(t *testing.T) {
	// `server add` fails through the exit code (log.Fatal on a non-200), so the
	// error carries whatever the CLI printed.
	runner := &fakeRunner{
		stdout: "some standard output",
		stderr: "Request failed, server responded: 404 - pool not found",
		err:    errors.New("exit status 1"),
	}
	cli := newTestCLI(runner)

	err := cli.AddServer(context.Background(), testConfigPath, "missing.example.com", "http://10.0.0.5:32768", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not add the backend")
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "pool not found")
	assert.Contains(t, err.Error(), "some standard output")
}

func TestAddServerRequiresAddress(t *testing.T) {
	runner := &fakeRunner{}
	cli := newTestCLI(runner)

	err := cli.AddServer(context.Background(), testConfigPath, "my-app.example.com", "  ", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no address")
	assert.Empty(t, runner.calls)
}

func TestPoolConfigParsesOnlyStandardOutput(t *testing.T) {
	// Everything the CLI logs goes to stderr, timestamp prefix included: only
	// `pool config --json` writes clean JSON on stdout.
	runner := &fakeRunner{
		stdout: samplePoolJson,
		stderr: "2026/08/13 10:00:00 some log line that is not JSON\n",
	}
	cli := newTestCLI(runner)

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.NoError(t, err)
	require.NotNil(t, pool)
	assert.Equal(t, "my-app.example.com", pool.Hostname)

	server, found := pool.FindByAddress("http://10.0.0.5:32768")
	require.True(t, found)
	assert.Equal(t, "cbfca8b3-6a2f-4f7c-8b60-4a5f5a2c1d11", server.Id)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, buildPoolConfigArgs(testConfigPath, "my-app.example.com"), runner.calls[0].args)
}

func TestPoolConfigCommandFailure(t *testing.T) {
	runner := &fakeRunner{stderr: "Request failed, server responded: 404 - pool not found", err: errors.New("exit status 1")}
	cli := newTestCLI(runner)

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "missing.example.com")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "pool not found")
}

func TestPoolConfigEmptyOutput(t *testing.T) {
	runner := &fakeRunner{stdout: "  \n"}
	cli := newTestCLI(runner)

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "no pool configuration")
}

func TestPoolConfigInvalidJson(t *testing.T) {
	runner := &fakeRunner{stdout: "not json at all"}
	cli := newTestCLI(runner)

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "cannot parse the pool configuration")
}

func TestPoolConfigTimeout(t *testing.T) {
	runner := &fakeRunner{deadline: true}
	cli := newTestCLI(runner)

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "did not complete within 1s")
}

func TestRemoveServer(t *testing.T) {
	runner := &fakeRunner{stderr: "Server cbfca8b3 removed successfully from pool my-app.example.com\n"}
	cli := newTestCLI(runner)

	err := cli.RemoveServer(context.Background(), testConfigPath, "my-app.example.com", "cbfca8b3")
	require.NoError(t, err)

	require.Len(t, runner.calls, 1)
	assert.Equal(t, buildServerDelArgs(testConfigPath, "my-app.example.com", "cbfca8b3"), runner.calls[0].args)
}

func TestRemoveServerCommandFailure(t *testing.T) {
	runner := &fakeRunner{stderr: "server cbfca8b3 not found in pool", err: errors.New("exit status 1")}
	cli := newTestCLI(runner)

	err := cli.RemoveServer(context.Background(), testConfigPath, "my-app.example.com", "cbfca8b3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server cbfca8b3 not found in pool")
}

func TestRemoveServerRequiresUUID(t *testing.T) {
	runner := &fakeRunner{}
	cli := newTestCLI(runner)

	err := cli.RemoveServer(context.Background(), testConfigPath, "my-app.example.com", " ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no continuity backend identifier")
	assert.Empty(t, runner.calls)
}

func TestCLIDefaults(t *testing.T) {
	runner := &fakeRunner{stdout: samplePoolJson}
	// Neither the binary nor the timeout configured: $PATH lookup and the
	// 90s bound sitting above the ~51s a transaction can take server side.
	cli := &CLI{run: runner.run}

	_, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.NoError(t, err)
	require.Len(t, runner.calls, 1)
	assert.Equal(t, DefaultBin, runner.calls[0].bin)

	assert.Equal(t, DefaultTimeout, NewCLI("").Timeout)
	assert.Equal(t, "/usr/local/bin/continuity", NewCLI("/usr/local/bin/continuity").Bin)
}

func TestCLIWithMissingBinary(t *testing.T) {
	// The real runner: a misconfigured continuity_bin must surface as an
	// error, never as a panic or a silent success.
	cli := NewCLI(filepath.Join(t.TempDir(), "there-is-no-continuity-here"))

	err := cli.Transaction(context.Background(), testConfigPath, "my-app.example.com", "http://10.0.0.5:32768", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not run the transaction")

	pool, err := cli.PoolConfig(context.Background(), testConfigPath, "my-app.example.com")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "could not read the pool configuration")
}
