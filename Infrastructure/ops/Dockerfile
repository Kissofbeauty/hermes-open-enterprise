# Daily log collection + backups. No network, no Docker socket.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache bash coreutils findutils jq tar gzip age tzdata

COPY scripts/ /ops/
COPY crontab /etc/crontabs/root
RUN chmod 0755 /ops/*.sh && chmod 0600 /etc/crontabs/root

# busybox crond in the foreground; job output goes to the container log
CMD ["crond", "-f", "-l", "8", "-d", "8"]
