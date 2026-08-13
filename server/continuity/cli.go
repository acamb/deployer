package continuity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// DefaultBin is the name of the continuity CLI, looked up in $PATH when
	// ServerConfiguration.ContinuityBin is empty.
	DefaultBin = "continuity"
	// DefaultTimeout bounds every invocation of the CLI. It sits above the
	// ~51s a transaction can take server side (initial delay + timeout * numOk
	// * 2 + 1s with the continuity defaults), because the CLI polls the
	// transaction forever without any timeout of its own: without this bound a
	// deploy against an unreachable continuity would hang the server.
	DefaultTimeout = 90 * time.Second
	// transactionErrorMarker is what the continuity CLI logs on a rolled back
	// transaction. It is the only evidence available, since the CLI exits 0
	// even when the transaction failed.
	transactionErrorMarker = "completed with error:"
)

// CLI invokes the continuity command line client as a subprocess, the same way
// deployer already invokes `docker compose` and `ekvs`.
//
// Every method returns an error instead of terminating the process: the Go
// client of continuity is built around log.Fatal, which is unacceptable inside
// the deployer server.
type CLI struct {
	// Bin is the path of the continuity binary; empty means DefaultBin.
	Bin string
	// Timeout bounds a single invocation; zero means DefaultTimeout.
	Timeout time.Duration
	// run executes the command. It is only ever replaced by the tests.
	run runner
}

// runner executes bin with args and returns its standard output and standard
// error separately: only stdout carries machine readable output.
type runner func(ctx context.Context, bin string, args ...string) (stdout []byte, stderr []byte, err error)

// NewCLI returns a CLI invoking bin, or the binary found in $PATH when bin is
// empty, with the default timeout.
func NewCLI(bin string) *CLI {
	return &CLI{Bin: bin, Timeout: DefaultTimeout}
}

// Transaction adds address as a backend of pool and, when removeUUID is not
// empty, removes that backend in the same transaction: this is what makes a
// deploy zero downtime, as continuity waits for the new backend to be healthy
// before dropping the old one.
func (c *CLI) Transaction(ctx context.Context, cfgPath, pool, address, healthCheck, removeUUID string) error {
	if strings.TrimSpace(address) == "" {
		return errors.New("no address to publish as a continuity backend")
	}
	stdout, stderr, err := c.execute(ctx, buildTransactionArgs(cfgPath, pool, address, healthCheck, removeUUID))
	// The rolled back transaction is reported on stderr and *not* through the
	// exit code, so stderr is inspected before err: it carries the reason.
	if message := transactionErrorMessage(stderr); message != "" {
		return fmt.Errorf("the continuity transaction was rolled back: %s", message)
	}
	if err != nil {
		return commandError("run the transaction", stdout, stderr, err)
	}
	return nil
}

// PoolConfig returns the current configuration of a pool. It is the only
// command of the continuity CLI printing clean JSON on stdout, hence the only
// way to resolve an address to the UUID continuity assigned to that backend.
func (c *CLI) PoolConfig(ctx context.Context, cfgPath, pool string) (*Pool, error) {
	stdout, stderr, err := c.execute(ctx, buildPoolConfigArgs(cfgPath, pool))
	if err != nil {
		return nil, commandError("read the pool configuration", stdout, stderr, err)
	}
	// Only stdout is parsed: everything else the CLI prints, logs included,
	// goes to stderr with a timestamp prefix and would break the JSON.
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, errors.New("the continuity CLI returned no pool configuration")
	}
	var parsed Pool
	if err := json.Unmarshal(stdout, &parsed); err != nil {
		return nil, fmt.Errorf("cannot parse the pool configuration returned by the continuity CLI: %v", err)
	}
	return &parsed, nil
}

// RemoveServer removes the backend identified by uuid from pool.
func (c *CLI) RemoveServer(ctx context.Context, cfgPath, pool, uuid string) error {
	if strings.TrimSpace(uuid) == "" {
		return errors.New("no continuity backend identifier to remove")
	}
	stdout, stderr, err := c.execute(ctx, buildServerDelArgs(cfgPath, pool, uuid))
	if err != nil {
		return commandError("remove the backend", stdout, stderr, err)
	}
	return nil
}

// buildTransactionArgs returns the argv of a transaction.
//
// --pool is omitted when empty, letting continuity fall back to the
// default_pool of the configuration; --health-check is omitted when empty,
// letting it fall back to its own /health default; --remove-server is omitted
// when no previous backend could be resolved, because an unknown UUID makes
// the whole call fail *before* the new backend is added.
func buildTransactionArgs(cfgPath, pool, address, healthCheck, removeUUID string) []string {
	args := configArgs(cfgPath)
	args = append(args, "server", "transaction")
	args = appendFlag(args, "--pool", pool)
	args = append(args, "--address", address)
	args = appendFlag(args, "--health-check", healthCheck)
	args = appendFlag(args, "--remove-server", removeUUID)
	return args
}

// buildPoolConfigArgs returns the argv reading the configuration of a pool.
// The pool is a positional argument here, not a flag, and is omitted when
// empty so that continuity uses its default_pool.
func buildPoolConfigArgs(cfgPath, pool string) []string {
	args := configArgs(cfgPath)
	args = append(args, "pool", "config")
	if pool = strings.TrimSpace(pool); pool != "" {
		args = append(args, pool)
	}
	return append(args, "--json")
}

// buildServerDelArgs returns the argv removing a backend. The subcommand is
// `del`, not `remove`.
func buildServerDelArgs(cfgPath, pool, uuid string) []string {
	args := configArgs(cfgPath)
	args = append(args, "server", "del")
	args = appendFlag(args, "--pool", pool)
	return append(args, "--server", uuid)
}

func configArgs(cfgPath string) []string {
	return []string{"-f", cfgPath}
}

func appendFlag(args []string, flag, value string) []string {
	if value = strings.TrimSpace(value); value == "" {
		return args
	}
	return append(args, flag, value)
}

// execute runs the CLI under a deadline and turns an expired context into a
// dedicated error: the CLI polls a pending transaction once a second forever,
// so a continuity that never answers would otherwise block the caller.
func (c *CLI) execute(ctx context.Context, args []string) ([]byte, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	bin := strings.TrimSpace(c.Bin)
	if bin == "" {
		bin = DefaultBin
	}
	run := c.run
	if run == nil {
		run = execRunner
	}
	callContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, err := run(callContext, bin, args...)
	if errors.Is(callContext.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return stdout, stderr, fmt.Errorf("the continuity CLI did not complete within %s", timeout)
	}
	return stdout, stderr, err
}

func execRunner(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// transactionErrorMessage extracts the reason of a rolled back transaction
// from the log lines of the CLI, and returns an empty string when the
// transaction succeeded.
func transactionErrorMessage(stderr []byte) string {
	for _, line := range strings.Split(string(stderr), "\n") {
		if index := strings.Index(line, transactionErrorMarker); index >= 0 {
			message := strings.TrimSpace(line[index+len(transactionErrorMarker):])
			if message == "" {
				message = "no reason reported"
			}
			return message
		}
	}
	return ""
}

// commandError builds an error carrying whatever the CLI printed: an exit
// status alone says nothing about what went wrong on the continuity side.
func commandError(operation string, stdout, stderr []byte, err error) error {
	message := fmt.Sprintf("the continuity CLI could not %s: %v", operation, err)
	if details := strings.TrimSpace(string(stderr)); details != "" {
		message += ". Stderr: " + details
	}
	if details := strings.TrimSpace(string(stdout)); details != "" {
		message += ". Stdout: " + details
	}
	return errors.New(message)
}
