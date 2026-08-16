# Build the `continuity` CLI static (musl-compatible), pinned to the same
# version as the continuity-server image (version lockstep). Continuity does
# not publish a static CLI release asset, so we build it from source here.
ARG CONTINUITY_VERSION=0.2.0
FROM golang:alpine AS continuity-build
ARG CONTINUITY_VERSION
RUN apk add --no-cache git
RUN git clone --branch v${CONTINUITY_VERSION} --depth 1 https://github.com/acamb/continuity.git /src \
    && cd /src \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
        -ldflags "-s -w -X 'continuity/client/version.Version=${CONTINUITY_VERSION}'" \
        -o /continuity ./client/cmd

FROM docker:cli
ARG SSH_PUBLIC_KEY
ARG HOST_RSA_KEY

RUN apk add --no-cache bash wget
RUN wget https://github.com/acamb/ekvs/releases/latest/download/cli-static -O /usr/bin/ekvs && chmod +x /usr/bin/ekvs
COPY --from=continuity-build /continuity /usr/bin/continuity
RUN chmod +x /usr/bin/continuity

# Create user and directory
RUN addgroup -S deployer-server && \
    adduser -S -D -H -G deployer-server -s /sbin/nologin deployer-server && \
    mkdir -p /opt/deployer && chown deployer-server:deployer-server /opt/deployer && \
    printf "%s" "${HOST_RSA_KEY}" > /opt/deployer/host_rsa_key && \
    chown deployer-server:deployer-server /opt/deployer/host_rsa_key && chmod 600 /opt/deployer/host_rsa_key && \
    printf "port: 7676\nlistenAddress: 0.0.0.0\nworkingDirectory: /opt/deployer\nhostKeyPath: /opt/deployer/host_rsa_key\n" > /opt/deployer/config.yaml && \
    chown deployer-server:deployer-server /opt/deployer/config.yaml

# Authorized SSH keys
RUN printf "%s" "${SSH_PUBLIC_KEY}" > /opt/deployer/authorized_keys && \
    chown deployer-server:deployer-server /opt/deployer/authorized_keys && \
    chmod 600 /opt/deployer/authorized_keys

CMD ["/bin/sh","-c","/usr/bin/deployer-server -config /opt/deployer/config.yaml"]
