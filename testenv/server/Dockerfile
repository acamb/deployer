FROM docker:cli
ARG SSH_PUBLIC_KEY
ARG HOST_RSA_KEY

RUN apk add --no-cache bash

# Crea utente e directory
RUN addgroup -S deployer-server && \
    adduser -S -D -H -G deployer-server -s /sbin/nologin deployer-server && \
    mkdir -p /opt/deployer && chown deployer-server:deployer-server /opt/deployer && \
    printf "%s" "${HOST_RSA_KEY}" > /opt/deployer/host_rsa_key && \
    chown deployer-server:deployer-server /opt/deployer/host_rsa_key && chmod 600 /opt/deployer/host_rsa_key && \
    printf "port: 7676\nlistenAddress: 0.0.0.0\nworkingDirectory: /opt/deployer\nhostKeyPath: /opt/deployer/host_rsa_key\n" > /opt/deployer/config.yaml && \
    chown deployer-server:deployer-server /opt/deployer/config.yaml

# Chiavi SSH autorizzate
RUN printf "%s" "${SSH_PUBLIC_KEY}" > /opt/deployer/authorized_keys && \
    chown deployer-server:deployer-server /opt/deployer/authorized_keys && \
    chmod 600 /opt/deployer/authorized_keys

CMD ["/bin/sh","-c","/usr/bin/deployer-server -config /opt/deployer/config.yaml"]
