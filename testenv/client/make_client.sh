#!/bin/bash
# Builds the deployer client for the HOST it runs on (not for a container), so
# it works both on Linux and on Windows via git bash. The output gets a .exe
# suffix on Windows.
set -e
cd ../../

EXT=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXT=".exe" ;;
esac

go build -o "bin/deployer-client_dev${EXT}" ./client/cmd
if [ -z "$EXT" ]; then
  chmod +x bin/deployer-client_dev
fi

cd "$OLDPWD"
