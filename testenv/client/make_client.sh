#!/bin/bash
cd ../../
GOOS=linux GOARCH=amd64 go build -o bin/deployer-client_dev ./client/cmd
chmod +x bin/deployer-client_dev
cd $OLDPWD
