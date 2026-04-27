FROM alpine:3.19

# tcpdump + libcap (the latter so we can chown captured files via shell).
RUN apk add --no-cache tcpdump

# No ENTRYPOINT — runner passes the full tcpdump argv at `docker run` time.
