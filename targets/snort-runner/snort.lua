# Minimal Snort 3 (Snort++) config for OFFLINE pcap replay.
-- Lua syntax — alpine ships Snort++ 3.x in its community repo.
HOME_NET     = 'any'
EXTERNAL_NET = 'any'

-- Loopback traffic on Linux skips checksum offload, so every TCP packet in
-- our captured pcap has a "bad" L4 checksum. Without this, Snort discards
-- 100% of the packets and never reaches the rule engine.
network = {
    checksum_eval = 'none',
}

ips = {
    -- Load the pinned Log4Shell ruleset shipped alongside this config.
    include = '/etc/snort/rules/log4shell.rules',
}

-- Write `alert_fast.txt` into the log dir we mount as /out.
alert_fast = {
    file = true,
    packet = false,
}
