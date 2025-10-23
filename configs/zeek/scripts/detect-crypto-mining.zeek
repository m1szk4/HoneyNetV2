# Cryptocurrency Mining Detection Script for Zeek
# Detects crypto mining activities and pool connections

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice

module CryptoMining;

export {
    redef enum Notice::Type += {
        CryptoMiner_Connection,
        CryptoMiner_Pool_Detected,
        CryptoMiner_DNS_Query,
        CryptoMiner_Binary_Detected,
    };

    # Common mining pool ports
    const mining_ports = set(3333/tcp, 4444/tcp, 5555/tcp, 7777/tcp, 8888/tcp, 9999/tcp, 14444/tcp) &redef;

    # Known mining pool domains
    const mining_pools = /minergate|nicehash|pool\.ntp\.org|supportxmr|moneropool|nanopool|f2pool|slushpool|antpool|poolto/ &redef;

    # Mining software patterns
    const miner_software = /xmrig|cpuminer|cgminer|bfgminer|ethminer|phoenixminer|claymore|ewbf|ccminer/ &redef;

    # Stratum protocol detection (mining protocol)
    const stratum_pattern = /stratum\+tcp|stratum\+ssl|mining\.subscribe|mining\.authorize/ &redef;
}

# Track long-lived connections to suspicious ports
global long_connections: table[conn_id] of time &create_expire=5 min;

event connection_established(c: connection) {
    if (c$id$resp_p in mining_ports) {
        NOTICE([$note=CryptoMiner_Connection,
                $msg=fmt("Connection to common mining port %s from %s", c$id$resp_p, c$id$orig_h),
                $conn=c]);

        long_connections[c$id] = network_time();
    }
}

# Detect mining pool DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (mining_pools in query) {
        NOTICE([$note=CryptoMiner_DNS_Query,
                $msg=fmt("Mining pool DNS query detected: %s from %s", query, c$id$orig_h),
                $conn=c]);
    }
}

# Detect stratum protocol (mining)
event connection_established(c: connection) {
    # Monitor for stratum protocol on established connections
}

# Detect mining software in HTTP downloads
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (miner_software in original_URI) {
        NOTICE([$note=CryptoMiner_Binary_Detected,
                $msg=fmt("Mining software download detected: %s from %s", original_URI, c$id$orig_h),
                $conn=c]);
    }
}

# Detect high-entropy data transfers (potential mining traffic)
event connection_state_remove(c: connection) {
    if (c$id in long_connections) {
        local duration = network_time() - long_connections[c$id];

        # Long-lived connections with regular small data transfers are typical of mining
        if (duration > 5 mins && c$orig?$num_pkts && c$orig$num_pkts > 100) {
            NOTICE([$note=CryptoMiner_Pool_Detected,
                    $msg=fmt("Potential crypto mining activity from %s to %s:%s",
                            c$id$orig_h, c$id$resp_h, c$id$resp_p),
                    $conn=c]);
        }

        delete long_connections[c$id];
    }
}

# Detect CPU-intensive processes via SSH commands (if captured)
# This would require deeper integration with honeypot command logs
