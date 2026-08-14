#!/bin/bash
# Sets up the deployer test environment (deployer-server + dind + continuity)
# and starts it. Cross-platform: works on Linux and on Windows via git bash.
# No sudo and no dependency on system files: all keys are generated here.
set -e

SSH_DIR="$HOME/.ssh"
mkdir -p "$SSH_DIR"

# Generate a passphrase-less key only if it does not already exist (idempotent,
# never prompts to overwrite). $1 = path, $2 = key type.
gen_key() {
  if [ ! -f "$1" ]; then
    echo "Generating key $1"
    ssh-keygen -t "$2" -N "" -f "$1" -C "$(basename "$1")"
  fi
}

# deployer-server SSH host key (baked into the image via the HOST_RSA_KEY arg).
# The client auto-trusts it on first connection (TOFU).
gen_key "./host_rsa_key" rsa
# deployer client SSH auth key. Dedicated key so we never touch ~/.ssh/id_ed25519;
# testenv/client/config.yaml references it via private_key.
gen_key "$SSH_DIR/deployer_test" ed25519
# continuity auth key. Passphrase-less (continuity does not support passphrases);
# the client sends it to the server (path A) and its public part authorizes it
# on continuity below.
gen_key "$SSH_DIR/continuity_test" ed25519

# authorized_keys for the continuity management API (mounted into the container).
cp "$SSH_DIR/continuity_test.pub" ./continuity-authorized-keys

HOST_RSA_KEY=$(cat ./host_rsa_key)
SSH_PUBLIC_KEY=$(cat "$SSH_DIR/deployer_test.pub")
export HOST_RSA_KEY SSH_PUBLIC_KEY

# statically linked for alpine linux (dind image)
./make_server.sh
docker compose up --build
