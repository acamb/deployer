![deployer_banner.svg](img/deployer_banner.svg)

![Test Status](https://github.com/acamb/deployer/actions/workflows/makefile.yml/badge.svg)

A secure SSH-based deployment system for remote Docker container management.

Deployer is designed for homelabs and small infrastructure setups where you need simple, secure Docker deployments without the complexity of setting up a Docker registry. Instead of managing registry infrastructure, Deployer transfers Docker images directly from your development machine to the target server over SSH, making it perfect for personal projects, small teams, and homelab environments.

## Features

- **Docker Integration**: Deploy and manage Docker containers remotely: deploy, start, stop, and view logs
- **Secure Communication**: All data encrypted over SSH channels, public key authentication and host key verification
- **Revisions**: deploy multiple revisions of your application, roll back to previous versions easily
- **Load balancer integration**: optionally register deployed containers as backends on a [Continuity](https://github.com/acamb/continuity) pool for zero-downtime deployments, with periodic reconciliation

## Architecture

The system consists of two components:
- **Server**: SSH server that manages Docker containers
- **Client**: CLI tool for deployment and container management

## How It Works

Deployer simplifies Docker deployments using just two files in your project directory:

### Project Files
- **`Dockerfile`** *(optional)*: Client builds the Docker image locally
- **`compose.yml`** *(required)*: Server uses this to orchestrate the container

### Deployment Process
1. **`deployer-client deploy`**: Builds image (if Dockerfile exists), packages everything, and sends to server via SSH
2. **Server**: Receives the image and compose file, imports the image, then uses `docker-compose` to manage the container

### Remote Management
All container operations (`start`, `stop`, `restart`, `logs`) are executed on the server using docker-compose commands. Communication is secured through SSH with public key authentication.

### Deployment Options
- **With Dockerfile**: Full build and deploy - client builds image locally and transfers it
- **Compose only**: Use existing images from registries - faster for updates using pre-built images

The client supports also building through docker compose, mixing both methods as needed.

## Server Setup - Debian Package Installation (Recommended)

### 1. Download and Install Package

```bash
# Download the latest release
wget https://github.com/your-username/deployer/releases/download/vX.Y.Z/deployer-server_X.Y.Z_amd64.deb

# Install the package
sudo apt install /path/to/deployer-server_X.Y.Z_amd64.deb
```

The package automatically:
- Creates `deployer-server` system user
- Sets up systemd service
- Creates working directory `/opt/deployer`
- Generates SSH host key at `/opt/deployer/host_rsa_key`
- Adds user to docker group
- Starts the service

### 2. Add Client Public Keys

```bash
# Add client public keys to authorized_keys (one per line)
sudo -u deployer-server tee -a /opt/deployer/authorized_keys <<< "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
```

### 3. Verify Installation

```bash
# Check server is running
sudo systemctl status deployer-server

# Check server is listening
ss -tlnp | grep :7676

# Verify file permissions
ls -la /opt/deployer/authorized_keys  # Should be 600
ls -la /opt/deployer/host_rsa_key     # Should be 600

# Test SSH connection (optional)
ssh -p 7676 deployer@localhost
```

### 4. Service Management

```bash
# Restart service after configuration changes
sudo systemctl restart deployer-server

# Stop/start service
sudo systemctl stop deployer-server
sudo systemctl start deployer-server

# View logs
sudo journalctl -u deployer-server -f
```

---

## Server Setup - Manual Installation

### 1. Build the Server

```bash
# Clone repository
git clone https://github.com/acamb/deployer.git
cd deployer

# Build server and client
make all

# Or build individually
make server  # Creates bin/deployer-server
make client  # Creates bin/deployer-client
```

### 2. Create System User and Directory

```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin deployer-server

# Create working directory
sudo mkdir -p /opt/deployer
sudo chown deployer-server:deployer-server /opt/deployer

# Add user to docker group
sudo usermod -aG docker deployer-server
```

### 3. Generate SSH Host Key

```bash
# Generate SSH host key
sudo ssh-keygen -t rsa -b 4096 -f /opt/deployer/host_rsa_key -N ""
sudo chown deployer-server:deployer-server /opt/deployer/host_rsa_key
sudo chmod 600 /opt/deployer/host_rsa_key
```

### 4. Create Configuration File

```bash
# Create configuration file
sudo tee /opt/deployer/config.yaml <<EOF
port: 7676
listenAddress: 0.0.0.0
workingDirectory: /opt/deployer
hostKeyPath: /opt/deployer/host_rsa_key
EOF

sudo chown deployer-server:deployer-server /opt/deployer/config.yaml
```

### 5. Setup Authorized Keys

```bash
# Create authorized_keys file
sudo touch /opt/deployer/authorized_keys
sudo chmod 600 /opt/deployer/authorized_keys
sudo chown deployer-server:deployer-server /opt/deployer/authorized_keys

# Add client public keys (one per line)
sudo -u deployer-server tee -a /opt/deployer/authorized_keys <<< "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
```

### 6. Install and Start Service

```bash
# Copy binary to system path
sudo cp bin/deployer-server /usr/bin/

# Create systemd service (optional but recommended)
sudo tee /etc/systemd/system/deployer-server.service <<EOF
[Unit]
Description=Deployer Server
After=network.target

[Service]
Type=simple
User=deployer-server
Group=deployer-server
ExecStart=/usr/bin/deployer-server -config /opt/deployer/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable deployer-server
sudo systemctl start deployer-server
```

### 7. Verify Installation

```bash
# Check server is running
sudo systemctl status deployer-server

# Check server is listening
ss -tlnp | grep :7676

# Verify file permissions
ls -la /opt/deployer/authorized_keys  # Should be 600
ls -la /opt/deployer/host_rsa_key     # Should be 600

# Test SSH connection (optional)
ssh -p 7676 deployer@localhost
```

---

## Configuration Parameters

- **port**: SSH server listening port (default: 7676)
- **listenAddress**: Bind address (default: 0.0.0.0)
- **workingDirectory**: Working directory for containers (default: /opt/deployer)
- **hostKeyPath**: SSH host key path (default: /opt/deployer/host_rsa_key)
- **ekvs_bin**: path to the `ekvs` CLI binary (optional; defaults to `ekvs` from PATH)
- **continuity_bin**: path to the `continuity` CLI binary (optional; defaults to `continuity` from PATH). See [Continuity Integration](#continuity-integration)

**⚠️ Security Requirements:**
- `authorized_keys` file permissions: `600` (read/write owner only)
- `host_rsa_key` file permissions: `600` (read/write owner only)
- Owner: same user running the server (`deployer-server`)
- Format: one public key per line (OpenSSH standard format)

## Client Setup - Debian Package Installation (Recommended)

### 1. Download and Install Package

```bash
# Download the latest release
wget https://github.com/your-username/deployer/releases/download/vX.Y.Z/deployer-client_X.Y.Z_amd64.deb

# Install the package
sudo apt install /path/to/deployer-client_X.Y.Z_amd64.deb
```

The package automatically:
- Installs `deployer-client` binary in `/usr/bin/`

### 2. Configure Client

Create a configuration file for each project / deployment:

```bash
# Create configuration file
nano client-config.yaml
```

Example configuration:

```yaml
host: your-server-host
port: 7676
name: myapp
image_name: myapp:latest
#the private key is optional, by default the user keys are used.
private_key: /path/to/your/private/key
```

### 3. Generate SSH Key Pair (if needed)

If you don't have an SSH key pair, create one:

```bash
# Generate SSH key pair for client authentication
ssh-keygen -t rsa -b 4096 -f ~/.ssh/deployer_key -N ""

# Set correct permissions
chmod 600 ~/.ssh/deployer_key
chmod 644 ~/.ssh/deployer_key.pub
```

### 4. Authorize Client on Server

Add your public key to the server's authorized_keys:

```bash
# Copy your public key
cat ~/.ssh/deployer_key.pub
# Add this key to server's /opt/deployer/authorized_keys file
```

---

## Client Setup - Manual Installation

### 1. Generate SSH Key Pair (optional, you can use existing keys)

```bash
# Generate SSH key pair for client authentication
ssh-keygen -t rsa -b 4096 -f ~/.ssh/deployer_key -N ""

# Set correct permissions
chmod 600 ~/.ssh/deployer_key
chmod 644 ~/.ssh/deployer_key.pub
```

### 2. Authorize Client on Server

Copy the client's public key to the server's `authorized_keys` file:

```bash
# Method 1: Manual copy (most common)
cat ~/.ssh/deployer_key.pub
# Copy the output and add it to server's /opt/deployer/authorized_keys

# Method 2: Using scp
scp ~/.ssh/deployer_key.pub user@server-host:/tmp/
# Then on server: sudo -u deployer-server tee -a /opt/deployer/authorized_keys < /tmp/deployer_key.pub
```

### 3. Create Client Configuration

Create a YAML configuration file (e.g., `client-config.yaml`) for each project or deployment:

```yaml
host: your-server-host
port: 7676
name: myapp
image_name: myapp:latest
```

**Configuration Parameters:**
- **host**: Deployer server hostname or IP address
- **port**: Deployer server port (default: 7676)
- **name**: Unique deployment identifier
- **image_name**: Docker image name to deploy
- **private_key**: Path to SSH private key (optional, defaults to user's SSH keys)
- **build_method**: 'dockerfile' or 'compose' (default: 'dockerfile')
- **enable_revisions**: true/false (default: false)
- **revisions_remove_previous**: after a successful `--new-revision` deploy, stop the revision(s) that were running before (optional, default: false). See [Revisions](#revisions)
- **ekvs_enable / ekvs_server / ekvs_project / ekvs_private_key**: EKVS secret injection (optional). See [EKVS Integration](#ekvs-integration)
- **continuity_enable**: enable the Continuity load balancer integration (optional, default: false)
- **continuity_config**: path to a Continuity CLI config file (`host`/`port`/`default_pool`/`auth_key`) whose contents are forwarded to the server (required when `continuity_enable`)
- **continuity_pool**: target Continuity pool; optional when the forwarded config sets `default_pool`
- **continuity_internal_port**: container port to publish as a backend, 1–65535 (required when `continuity_enable`)
- **continuity_health_check_path**: health check path, must start with `/` (optional; Continuity defaults to `/health`)
- **continuity_remove_previous**: remove the previous backend after registering the new one (optional, default: false)
- **continuity_advertise_base**: base URL, scheme included and without port or path (e.g. `http://10.0.0.5`), under which the container is reachable by Continuity (required when `continuity_enable`)
- **continuity_private_key**: path to the Continuity auth key managed by deployer (optional; if unset, `auth_key` in `continuity_config` is used if present, otherwise no authentication — see [Continuity Integration](#continuity-integration))

### 4. Build Client (if needed)

```bash
# If you built the server manually, the client is already built
# Otherwise, build just the client:
git clone https://github.com/acamb/deployer.git
cd deployer
make client  # Creates bin/deployer-client
```

## Usage

You must run the client from the project / deployment directory where you place your `compose.yml` and (optionally) `Dockerfile` files.
The `deploy` command will build the Docker image and will send the image and the compose.yml file to the server.
The server will use the compose.yml file to deploy and manage the container.

### Client Operations

```bash
deployer-client deploy [--prune] [--revision] [--new-revision] # Deploy application (and run docker image prune if specified)
deployer-client push [--prune] [--revision]
deployer-client start [--revision]                             # Start container
deployer-client stop [--revision]                              # Stop container
deployer-client restart [--revision]                           # Restart container
deployer-client logs [--revision]                              # View container logs
deployer-client revisions                                      # List running revisions of the application
deployer-client ports [--port] [--revision] [--json]           # List the ports published by the container
deployer-client lb-status [--json]                             # Show the Continuity load balancer pool the project is published on
```



### Revisions
Revisions are the Deployer way of versioning your deployments, keeping a separate image and container for each revision.
This allows you to easily roll back to previous versions of your application if needed, do zero-downtime and blue-green deployments by switching between revisions and more.
Each revision is kept in a separate folder on the server under the project working directory.

To enable revisions, add the following to your `compose.yml`:

```yaml
enable_revisions: true
```

You can create a new revision with the `--new-revision` flag during deployment:

```bash
deployer-client deploy --new-revision
```
All the commands (except `revisions`) accept a `--revision <revision_number>` flag to target a specific revision when the revisions are enabled.

#### Automatically stopping the previous revision
By default, deploying a new revision leaves the previous revision's container running. Set:

```yaml
revisions_remove_previous: true
```

to have the client, after a **successful** `--new-revision` deploy, stop the revision that was running before. It inspects the currently running revisions (as `revisions` does):
- if exactly one previous revision is running, it is stopped automatically;
- if more than one is running, you are prompted to choose which one(s) to stop (enter list numbers separated by comma/space, `all`, or leave empty to skip);
- if the terminal is not interactive (e.g. CI) and there is more than one candidate, removal is skipped with a warning.

The stopped revision's files are kept on the server, so you can still roll back to it. Removal is best-effort: a failure to stop a previous revision only warns and never fails an already-successful deploy.

### Build method
The client supports two build methods:
- **Dockerfile**: The client builds the Docker image locally using the provided Dockerfile
- **Compose build**: The client builds the Docker image using `docker-compose build`, allowing more complex build scenarios

You can specify the build method in the client configuration file:

```yaml
build_method: dockerfile  # or 'compose', defalt is 'dockerfile'
```

## EKVS Integration

Deployer can optionally integrate with [EKVS](https://github.com/acamb/ekvs)
(Easy Key Value Store) to inject secrets into the container environment at
start time. When enabled on the client, Deployer wraps the remote
`docker compose up -d` command with `ekvs cli ... exec`, so that secrets
stored in EKVS are exported as environment variables and picked up by the
compose file.

### Prerequisites
- An EKVS server reachable from the deployer server.
- The client's EKVS public key already registered on the EKVS server
  (under `/data/.keys/`) and the target project already created. Deployer
  does **not** create users or projects on EKVS automatically.
- The `ekvs` CLI installed on the deployer **server**. By default it is
  looked up in `PATH`; you can override it via `ekvs_bin` in the server
  configuration.

### Server configuration (optional)
```yaml
# /opt/deployer/config.yaml
# ...
ekvs_bin: /usr/local/bin/ekvs   # optional; defaults to `ekvs` from PATH
```

### Client configuration
```yaml
# client-config.yaml
host: your-server-host
port: 7676
name: myapp
image_name: myapp:latest

ekvs_enable: true
ekvs_server: https://ekvs.example.com
ekvs_project: myapp
ekvs_private_key: /path/to/ekvs_private_key
```

When `ekvs_enable: true`, the client reads `ekvs_private_key` and sends its
contents to the deployer server on every `deploy`, `start` and `restart`
command. The server writes the key to a temporary file with `0600`
permissions, uses it to invoke `ekvs cli`, and removes the file immediately
afterwards. The key is **never** persisted on the server nor logged.

### Compose file
Reference the secrets in your `compose.yml` as regular environment
variables — EKVS will populate them before `docker compose up` runs:

```yaml
services:
  myapp:
    image: myapp:latest
    environment:
      - DB_PASSWORD
      - API_TOKEN
```

### Secrets as files (`ekvs_files`)
Some applications read their secrets from a **file** at startup (for example a
`config.json` whose entire content is sensitive) rather than from environment
variables. Deployer can materialize EKVS secrets as files and bind-mount them
into the container automatically.

Each entry maps **one EKVS secret** — whose value is the **entire file
content** — to an absolute path inside the container:

```yaml
ekvs_enable: true
ekvs_server: https://ekvs.example.com
ekvs_project: myapp
ekvs_private_key: /path/to/ekvs_private_key

ekvs_files:
  - secret: app_config_json      # the secret value is the whole config.json
    mount_path: /app/config.json # where to mount it inside the container
  - secret: tls_key
    mount_path: /etc/app/tls.key
    writable: false              # optional; files are read-only by default
```

For each entry, the server runs
`ekvs --server ... --identity ... export <project> <secret> --output <path>`,
writing the file (mode `0600`) under `<working-dir>/.ekvs-secrets/`, and
injects the matching bind mount into the service named like `name` in your
compose file. You do **not** need to declare these volumes yourself — but the
compose file must contain a service whose name matches `name` (the same
requirement as revisions).

The files are (re)written on every `deploy`, `start` and `restart`, so their
contents stay in sync with EKVS. `ekvs_files` requires `ekvs_enable: true` and
can be combined with the environment-variable injection described above.

### Security notes
- The private key is transmitted over the SSH channel between client and
  server, which is already encrypted; nevertheless it is transmitted on
  every container-starting operation. Keep the key file with `600`
  permissions on the client.
- The server-side temporary key file is removed via `defer` even if the
  underlying command panics.
- Errors reported by `ekvs` (including EKVS server URLs) are forwarded to
  the client verbatim.
- Unlike environment-variable injection, which is ephemeral, files
  materialized via `ekvs_files` remain on the server's disk (mode `0600`,
  under `<working-dir>/.ekvs-secrets/`) for the container's lifetime, because
  they are the bind-mount sources. They are removed when the project's files
  are deleted (`stop` with file deletion). This is an inherent trade-off of
  mounting a secret as a file.

## Continuity Integration

Deployer can optionally integrate with [Continuity](https://github.com/acamb/continuity),
a lightweight load balancer, to automatically register the container it just
deployed as a backend on a Continuity pool, optionally removing the previous
backend. The server drives this integration by invoking the `continuity` CLI
as an external process (same approach used for the EKVS integration).

### Prerequisites
- A Continuity server reachable from the deployer server.
- A pool already created on Continuity for the project.
- The `continuity` CLI installed on the deployer **server**. By default it
  is looked up in `PATH`; you can override it via `continuity_bin` in the
  server configuration.
- **Version lockstep**: the `continuity` CLI on the deployer server must be
  the **same version** as the Continuity server. The CLI aborts every command
  when the versions differ.
- In the forwarded Continuity config, `host` must include the scheme
  (e.g. `http://continuity.example.com`, not `continuity.example.com`).
- `auth_key` must be an **absolute** path on the deployer **server** — Continuity
  does not expand `~`. In the deployer-managed key path (see below) the server
  fills this in for you.
- The Continuity auth key must **not** have a passphrase.
- The clock skew between the deployer server and the Continuity server must be
  under 30 s (the signature validity window used for authentication).

### Server configuration (optional)
```yaml
# /opt/deployer/config.yaml
# ...
continuity_bin: /usr/local/bin/continuity   # optional; defaults to `continuity` from PATH
```

### Client configuration
```yaml
# client-config.yaml
host: your-server-host
port: 7676
name: myapp
image_name: myapp:latest

continuity_enable: true
continuity_config: './continuity-client.yaml'
continuity_pool: 'myapp.example.com'
continuity_health_check_path: '/health'
continuity_internal_port: '8080'
continuity_remove_previous: true
continuity_advertise_base: 'http://10.0.0.5'        # required: base URL (scheme, no port/path)
# continuity_private_key: '~/.ssh/continuity_key'   # optional, see below
```

`continuity_config` points to a Continuity CLI configuration file
(`host`/`port`/`default_pool`/`auth_key`) whose contents are forwarded to the
deployer server on every `deploy`, `start` and `restart` command.

The private key used to authenticate against Continuity is handled through
these mutually exclusive paths:
- **Managed by deployer**: set `continuity_private_key` to a key file path.
  The client reads and sends its contents to the server, which stores a
  copy in the project's working directory and rewrites `auth_key` in the
  forwarded `continuity_config` to point at it.
- **Already present on the server**: leave `continuity_private_key` unset and
  set `auth_key` in `continuity_config` to an absolute path on the server.
  No key is sent; the server persists `continuity_config` unmodified,
  assuming its `auth_key` already points to a key placed manually on the
  server.
- **No authentication**: leave `continuity_private_key` unset and omit
  `auth_key` from `continuity_config`. Nothing is sent and the file is
  forwarded verbatim; use this when the Continuity server does not require
  authentication.

### Advertise address

The backend address registered on Continuity is
`<advertise_base>:<published_docker_port>`. The base comes solely from
`continuity_advertise_base` in the client (per-project) config and is
**required** when `continuity_enable` is true: a single deployer instance can
serve projects registered on different load balancers and reachable on
different networks, so the server has no default of its own.

The base must include the scheme and must not carry a port or path
(the published Docker port is appended automatically).

### Server-side state

For every project with the integration enabled, the server keeps a
directory under the working directory (state lives at the **project** level,
never per-revision):

```
/opt/deployer/<name>/.continuity/
    config.yaml    # the forwarded Continuity config (auth_key rewritten in the managed-key path)
    key            # the managed key, 0600 (only in the deployer-managed key path)
    state.json     # deploy parameters + the address of the current backend
```

The in-memory project registry is rebuilt at startup by scanning these
directories — there is no central index file.

### Readiness and reconciliation

- **Readiness gate**: until the server has completed its first reconciliation
  pass over all registered projects, every incoming request is rejected with a
  `NotReady` status and the client is told to retry in a few seconds. If
  Continuity is unreachable the pass still completes (errors are logged) so the
  server never stays blocked.
- **Reconciliation**: once at startup and then every minute, the server
  compares the real state (the port published by Docker) with what is
  configured on Continuity and repairs any drift — re-registering a backend
  after an ephemeral port change, a host reboot or a manual removal, and
  deregistering a project whose container is no longer publishing a port.
  Reconciliation only touches backends whose address is the project's current
  or previous address; unrelated backends in the same pool are left untouched.

### Deploy failure and rollback

When the integration is enabled, adding the container to the load balancer is
part of a successful deploy: the client reports the deploy as done only **after**
the backend has been registered on Continuity. If the registration fails — a
`continuity` CLI error, or a transaction that rolls back because the new backend
never becomes healthy — the deploy is reported as **failed** (`Ko`):

- **Deploying a new revision** (the previous revision is still running under its
  own container): the previous revision is kept active on the load balancer and
  the new revision's container is torn down (`docker compose down`, its files are
  kept for inspection or a retry). The Continuity transaction is atomic, so a
  rolled-back transaction leaves the previous backend healthy and untouched.
- **Otherwise** (revisions disabled, or redeploying the same revision, where the
  old container has already been replaced): the container is left running and the
  failure is reported; the periodic reconciliation retries the registration.

### Stop behavior

On `deployer stop`, the server deregisters the current backend from the pool
and clears the stored address, but keeps the rest of the project state, so that
if the container comes back up (Docker restart policy, manual `docker start`)
the next reconciliation re-registers it.

### Checking the load balancer

`deployer-client lb-status` shows the Continuity pool the project is published
on, with each backend and its health status (essentially the output of
`continuity pool config`):

```bash
deployer-client lb-status
# Pool: my-app.example.com
# - http://10.0.0.5:32768 [Healthy] health-check: /health (unconditional)

deployer-client lb-status --json   # same information as JSON
```

It relies on the state persisted at deploy time, so the project must have been
deployed at least once with the integration enabled.

### Security notes
- When `continuity_private_key` is set, the key is transmitted over the
  already-encrypted SSH channel between client and server on every
  container-starting operation, same as the EKVS integration. Keep the key
  file with `600` permissions on the client.
- Unlike the EKVS integration, the Continuity key (when managed by
  deployer) is persisted on the server rather than used ephemerally,
  because it is also needed by the periodic reconciliation check.

## Troubleshooting

### Authentication Errors

```bash
# Verify public key is in server's authorized_keys
ssh -i ~/.ssh/deployer_key deployer@server-host -p 7676

# Check server logs for authentication errors (package installation)
sudo journalctl -u deployer-server -f

# Check server logs for authentication errors (manual installation)
tail -f /var/log/deployer.log
```

### Permission Issues

```bash
# Check key permissions on client
ls -la ~/.ssh/deployer_key*
# Should be: 600 for private key, 644 for public key

# Check authorized_keys permissions on server
ssh server-host "ls -la /opt/deployer/authorized_keys"
# Should be: 600
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
