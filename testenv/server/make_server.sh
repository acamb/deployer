#!/bin/bash
#statically linked for alpine linux
cd ../../
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/deployer-server_dev ./server
cd $OLDPWD