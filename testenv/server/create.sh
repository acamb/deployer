#!/bin/bash
set -e
trap EXIT
HOST_RSA_KEY=`sudo cat /etc/ssh/ssh_host_rsa_key`
SSH_PUBLIC_KEY=`cat ~/.ssh/id_ed25519.pub`
export HOST_RSA_KEY SSH_PUBLIC_KEY
#statically linked for alpine linux (dind image)
./make_server.sh
docker compose up --build