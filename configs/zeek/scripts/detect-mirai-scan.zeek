##! Zeek script to detect Mirai botnet scanning behavior
##! Detects characteristics of Mirai-style Telnet/SSH scanning
##!
##! Author: HoneyNetV2 Project
##! MITRE ATT&CK: T1595.001 (Active Scanning), T1110.001 (Brute Force)

@load base/frameworks/notice
@load base/protocols/conn

module MiraiDetect;

export {
    redef enum Notice::Type += {
        ## Indicates a potential Mirai scan was detected
        Mirai_Scan_Detected,
        ## Indicates potential Mirai brute force activity
        Mirai_Bruteforce_Detected,
        ## Indicates Mirai-like credential attempt
        Mirai_Credential_Attempt,
    };

    ## Time window for tracking connection patterns (5 minutes)
    const scan_window = 5min &redef;

    ## Minimum number of failed Telnet connections to trigger alert
    const telnet_scan_threshold = 5 &redef;

    ## Minimum number of SSH connection attempts to trigger alert
    const ssh_scan_threshold = 8 &redef;

    ## Common Mirai target ports
    const mirai_target_ports: set[port] = {
        23/tcp,   # Telnet
        2323/tcp, # Alternative Telnet
        22/tcp,   # SSH
        8080/tcp, # HTTP alt
        8081/tcp, # HTTP alt
        80/tcp,   # HTTP
    } &redef;

    ## Table tracking connection attempts per source IP
    global telnet_attempts: table[addr] of count &create_expire=scan_window &default=0;
    global ssh_attempts: table[addr] of count &create_expire=scan_window &default=0;
    global mirai_ports_hit: table[addr] of set[port] &create_expire=scan_window;
}

## Connection state change event
event connection_state_remove(c: connection)
{
    local src = c$id$orig_h;
    local dst_port = c$id$resp_p;

    # Track Telnet connection attempts
    if (dst_port == 23/tcp || dst_port == 2323/tcp)
    {
        # Short-lived connections are typical of scanners
        if (c$duration < 10sec)
        {
            ++telnet_attempts[src];

            # Track ports hit by this source
            if (src !in mirai_ports_hit)
                mirai_ports_hit[src] = set();
            add mirai_ports_hit[src][dst_port];

            # Check if threshold exceeded
            if (telnet_attempts[src] >= telnet_scan_threshold)
            {
                NOTICE([$note=Mirai_Scan_Detected,
                        $src=src,
                        $msg=fmt("Potential Mirai Telnet scan from %s (%d attempts in %s)",
                                src, telnet_attempts[src], scan_window),
                        $sub=fmt("Ports targeted: %s", mirai_ports_hit[src]),
                        $identifier=cat(src)]);

                # Reset counter after alert
                telnet_attempts[src] = 0;
            }
        }
    }

    # Track SSH connection attempts
    if (dst_port == 22/tcp)
    {
        if (c$duration < 15sec)
        {
            ++ssh_attempts[src];

            if (src !in mirai_ports_hit)
                mirai_ports_hit[src] = set();
            add mirai_ports_hit[src][dst_port];

            if (ssh_attempts[src] >= ssh_scan_threshold)
            {
                NOTICE([$note=Mirai_Scan_Detected,
                        $src=src,
                        $msg=fmt("Potential Mirai SSH scan from %s (%d attempts in %s)",
                                src, ssh_attempts[src], scan_window),
                        $identifier=cat(src)]);

                ssh_attempts[src] = 0;
            }
        }
    }
}

## Detect multi-port scanning typical of Mirai
event Conn::log_conn(rec: Conn::Info)
{
    local src = rec$id$orig_h;
    local dst_port = rec$id$resp_p;

    # Check if this is a Mirai target port
    if (dst_port in mirai_target_ports)
    {
        # Initialize set if needed
        if (src !in mirai_ports_hit)
            mirai_ports_hit[src] = set();

        add mirai_ports_hit[src][dst_port];

        # If source has hit multiple Mirai ports, generate notice
        if (|mirai_ports_hit[src]| >= 3)
        {
            NOTICE([$note=Mirai_Bruteforce_Detected,
                    $src=src,
                    $msg=fmt("Multi-port Mirai-style scan from %s targeting %d different ports",
                            src, |mirai_ports_hit[src]|),
                    $sub=fmt("Ports: %s", mirai_ports_hit[src]),
                    $identifier=cat(src, "-multiport")]);
        }
    }
}

## Detect Mirai-specific patterns in Telnet/SSH traffic
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
{
    if (atype == Analyzer::ANALYZER_TELNET)
    {
        # Mirai often uses very short Telnet sessions for credential testing
        if (c$duration < 5sec)
        {
            local src = c$id$orig_h;

            NOTICE([$note=Mirai_Credential_Attempt,
                    $conn=c,
                    $msg=fmt("Rapid Telnet connection from %s (possible Mirai credential test)", src),
                    $identifier=cat(src, c$start_time)]);
        }
    }
}

## Log custom Mirai detection events
event zeek_init()
{
    Log::create_stream(MiraiDetect::LOG,
                      [$columns=record {
                          ts: time &log;
                          src_ip: addr &log;
                          detection_type: string &log;
                          telnet_attempts: count &log &optional;
                          ssh_attempts: count &log &optional;
                          ports_hit: set[port] &log &optional;
                          note: string &log &optional;
                      },
                      $path="mirai_detect"]);
}
