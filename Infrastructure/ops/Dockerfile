# Daily log collection + backups. No network, no Docker socket.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache bash coreutils findutils jq tar gzip age tzdata

COPY scripts/ /ops/
COPY crontab /etc/crontabs/root
RUN chmod 0755 /ops/*.sh && chmod 0600 /etc/crontabs/root

# busybox crond in the foreground; job output goes to the container log
CMD ["crond", "-f", "-l", "8", "-d", "8"]
