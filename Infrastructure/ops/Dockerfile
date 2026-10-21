# Daily log collection + backups. No network, no Docker socket.
FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk add --no-cache bash coreutils findutils jq tar gzip age tzdata

COPY scripts/ /ops/
COPY crontab /etc/crontabs/root
RUN chmod 0755 /ops/*.sh && chmod 0600 /etc/crontabs/root

# busybox crond in the foreground; job output goes to the container log
CMD ["crond", "-f", "-l", "8", "-d", "8"]
