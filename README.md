![deployer_banner.svg](img/deployer_banner.svg)

![Test Status](https://github.com/acamb/deployer/actions/workflows/makefile.yml/badge.svg)

A secure SSH-based deployment system for remote Docker container management.

Deployer is designed for homelabs and small infrastructure setups where you need simple, secure Docker deployments without the complexity of setting up a Docker registry. Instead of managing registry infrastructure, Deployer transfers Docker images directly from your development machine to the target server over SSH, making it perfect for personal projects, small teams, and homelab environments.

## Features

- **Docker Integration**: Deploy and manage Docker containers remotely: deploy, start, stop, and view logs
- **Secure Communication**: All data encrypted over SSH channels, public key authentication and host key verification
- **Revisions**: deploy multiple revisions of your application, roll back to previous versions easily

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
deployer-client deploy           # Deploy application
deployer-client start            # Start container
deployer-client stop             # Stop container
deployer-client restart          # Restart container
deployer-client logs             # View container logs
deployer-client revisions        # List running revisions of the application
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

### Build method
The client supports two build methods:
- **Dockerfile**: The client builds the Docker image locally using the provided Dockerfile
- **Compose build**: The client builds the Docker image using `docker-compose build`, allowing more complex build scenarios

You can specify the build method in the client configuration file:

```yaml
build_method: dockerfile  # or 'compose', defalt is 'dockerfile'
```

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
