.PHONY: all server client client-windows clean deb client-deb docker-client-deb rpm client-rpm docker-server-rpm docker-client-rpm release

BINDIR := bin
PKGDIR := pkg
VERSION := $(shell cat version)
DEBNAME := $(BINDIR)/deployer-server_$(VERSION)_amd64.deb
DEBNAME_CLIENT := $(BINDIR)/deployer-client_$(VERSION)_amd64.deb
RPMNAME := $(BINDIR)/deployer-server-$(VERSION)-1.x86_64.rpm
RPMNAME_CLIENT := $(BINDIR)/deployer-client-$(VERSION)-1.x86_64.rpm

all: server client

server:
	mkdir -p $(BINDIR)
	go build -ldflags "-X 'main.Version=$(VERSION)'" -o $(BINDIR)/deployer-server_$(VERSION) ./server

client:
	mkdir -p $(BINDIR)
	go build -ldflags "-X 'main.Version=$(VERSION)'" -o $(BINDIR)/deployer-client_$(VERSION) ./client/cmd

client-windows:
	mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "-X 'main.Version=$(VERSION)'" -o $(BINDIR)/deployer-client_$(VERSION).exe ./client/cmd

clean:
	rm -rf $(BINDIR) $(PKGDIR) $(DEBNAME) $(DEBNAME_CLIENT) $(RPMNAME) $(RPMNAME_CLIENT)

deb:
	rm -rf $(PKGDIR)
	mkdir -p $(PKGDIR)/DEBIAN
	mkdir -p $(PKGDIR)/usr/bin
	mkdir -p $(PKGDIR)/lib/systemd/system
	mkdir -p $(PKGDIR)/opt/deployer
	cp $(BINDIR)/deployer-server_$(VERSION) $(PKGDIR)/usr/bin/deployer-server
	cp deployer-server.service $(PKGDIR)/lib/systemd/system/
	cp config-default.yml $(PKGDIR)/opt/deployer/config.yaml
	echo "Package: deployer-server\nVersion: $(VERSION)\nSection: base\nPriority: optional\nArchitecture: amd64\nMaintainer: Your Name <you@example.com>\nDescription: Deployer server" > $(PKGDIR)/DEBIAN/control
	echo "#!/bin/sh\n\
    id -u deployer-server >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin deployer-server\n\
    getent group docker >/dev/null 2>&1 && usermod -aG docker deployer-server\n\
    if [ ! -f /opt/deployer/host_rsa_key ]; then\n\
        ssh-keygen -t rsa -b 4096 -f /opt/deployer/host_rsa_key -N '' -q\n\
    fi\n\
    chown -R deployer-server:deployer-server /opt/deployer\n\
    chmod 600 /opt/deployer/host_rsa_key\n\
    systemctl daemon-reload\n\
    systemctl enable deployer-server.service\n\
    systemctl start deployer-server.service\n\
    " > $(PKGDIR)/DEBIAN/postinst
	chmod 755 $(PKGDIR)/DEBIAN/postinst
	dpkg-deb --build $(PKGDIR) $(DEBNAME)

rpm:
	rm -rf $(PKGDIR)-rpm
	mkdir -p $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/usr/bin
	mkdir -p $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/lib/systemd/system
	mkdir -p $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/opt/deployer
	mkdir -p $(PKGDIR)-rpm/SPECS
	cp $(BINDIR)/deployer-server_$(VERSION) $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/usr/bin/deployer-server
	cp deployer-server.service $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/lib/systemd/system/
	cp config-default.yml $(PKGDIR)-rpm/BUILDROOT/deployer-server-$(VERSION)-1.x86_64/opt/deployer/config.yaml
	echo "Name: deployer-server" > $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Version: $(VERSION)" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Release: 1" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Summary: Deployer server" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "License: MIT" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Group: System Environment/Daemons" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "BuildArch: x86_64" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Requires: systemd" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "%description" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "Deployer server for application deployment" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "%post" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "id -u deployer-server >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin deployer-server" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "getent group docker >/dev/null 2>&1 && usermod -aG docker deployer-server" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "if [ ! -f /opt/deployer/host_rsa_key ]; then" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "    ssh-keygen -t rsa -b 4096 -f /opt/deployer/host_rsa_key -N '' -q" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "fi" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "chown -R deployer-server:deployer-server /opt/deployer" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "chmod 600 /opt/deployer/host_rsa_key" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "systemctl daemon-reload" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "systemctl enable deployer-server.service" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "systemctl start deployer-server.service" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "%files" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "/usr/bin/deployer-server" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "/lib/systemd/system/deployer-server.service" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	echo "/opt/deployer/config.yaml" >> $(PKGDIR)-rpm/SPECS/deployer-server.spec
	cd $(PKGDIR)-rpm && rpmbuild --define "_topdir $(PWD)/$(PKGDIR)-rpm" --define "_rpmdir $(PWD)/$(BINDIR)" -bb SPECS/deployer-server.spec

docker-server-deb-container:
	docker run --rm -v $(PWD):/workspace -w /workspace debian:bookworm bash -c "\
	apt-get update && \
	apt-get install -y ca-certificates make dpkg-dev && \
	make deb && \
	chown -R $(shell id -u):$(shell id -g) /workspace \
	"

docker-server-deb: server
	make docker-server-deb-container

client-deb:
	rm -rf $(PKGDIR)-client
	mkdir -p $(PKGDIR)-client/DEBIAN
	mkdir -p $(PKGDIR)-client/usr/bin
	cp $(BINDIR)/deployer-client_$(VERSION) $(PKGDIR)-client/usr/bin/deployer-client
	echo "Package: deployer-client\nVersion: $(VERSION)\nSection: base\nPriority: optional\nArchitecture: amd64\nMaintainer: Your Name <you@example.com>\nDescription: Deployer client CLI tool" > $(PKGDIR)-client/DEBIAN/control
	dpkg-deb --build $(PKGDIR)-client $(DEBNAME_CLIENT)

client-rpm:
	rm -rf $(PKGDIR)-client-rpm
	mkdir -p $(PKGDIR)-client-rpm/BUILDROOT/deployer-client-$(VERSION)-1.x86_64/usr/bin
	mkdir -p $(PKGDIR)-client-rpm/SPECS
	cp $(BINDIR)/deployer-client_$(VERSION) $(PKGDIR)-client-rpm/BUILDROOT/deployer-client-$(VERSION)-1.x86_64/usr/bin/deployer-client
	echo "Name: deployer-client" > $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "Version: $(VERSION)" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "Release: 1" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "Summary: Deployer client CLI tool" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "License: MIT" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "Group: Applications/System" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "BuildArch: x86_64" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "%description" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "Deployer client CLI tool for application deployment" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "%files" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	echo "/usr/bin/deployer-client" >> $(PKGDIR)-client-rpm/SPECS/deployer-client.spec
	cd $(PKGDIR)-client-rpm && rpmbuild --define "_topdir $(PWD)/$(PKGDIR)-client-rpm" --define "_rpmdir $(PWD)/$(BINDIR)" -bb SPECS/deployer-client.spec

docker-client-deb-container:
	docker run --rm -v $(PWD):/workspace -w /workspace debian:bookworm bash -c "\
	apt-get update && \
	apt-get install -y ca-certificates make dpkg-dev && \
	make client-deb && \
	chown -R $(shell id -u):$(shell id -g) /workspace \
	"

docker-client-deb: client
	make docker-client-deb-container

docker-server-rpm-container:
	docker run --rm -v $(PWD):/workspace -w /workspace rockylinux:9 bash -c "\
	yum update -y && \
	yum install -y ca-certificates make rpm-build && \
	make rpm && \
	chown -R $(shell id -u):$(shell id -g) /workspace \
	"

docker-server-rpm: server
	make docker-server-rpm-container

docker-client-rpm-container:
	docker run --rm -v $(PWD):/workspace -w /workspace rockylinux:9 bash -c "\
	yum update -y && \
	yum install -y ca-certificates make rpm-build && \
	make client-rpm && \
	chown -R $(shell id -u):$(shell id -g) /workspace \
	"

docker-client-rpm: client
	make docker-client-rpm-container

release: server client client-windows docker-server-deb docker-client-deb docker-server-rpm docker-client-rpm

check:
	cd client && go test -v ./... && cd ..
	cd client/config && go test -v ./... && cd ../..
	cd server && go test -v ./... && cd ..
	cd protocol && go test -v ./... && cd ..
