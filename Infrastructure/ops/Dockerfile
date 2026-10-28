# Daily log collection + backups. No network, no Docker socket.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache bash coreutils findutils jq tar gzip age tzdata

COPY scripts/ /ops/
COPY crontab /etc/crontabs/root
RUN chmod 0755 /ops/*.sh && chmod 0600 /etc/crontabs/root

# busybox crond in the foreground; job output goes to the container log
CMD ["crond", "-f", "-l", "8", "-d", "8"]
