# Offline Snort 3 (Snort++) replay container — receives a captured pcap
# via /in volume and writes alerts to /out/alert_fast.txt. Used by T7
# (Log4Shell probe) to bridge captured traffic into a real Snort
# detection chain without requiring a live sensor.
#
# Snort++ 3.x is shipped in alpine community repo. Offline replay is
# `snort -r capture.pcap -c snort.lua -A alert_fast -l /out -q`.

FROM alpine:3.19

RUN apk add --no-cache snort tini \
 && mkdir -p /etc/snort/rules /var/log/snort /in /out

COPY snort.lua        /etc/snort/snort.lua
COPY log4shell.rules  /etc/snort/rules/log4shell.rules

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["snort", "-c", "/etc/snort/snort.lua", "-r", "/in/capture.pcap", \
     "-A", "alert_fast", "-l", "/out", "-q"]
