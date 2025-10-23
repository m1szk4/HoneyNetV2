##! Local site policy for Zeek
##! Configuration for IoT Honeypot environment
##! Optimized for detecting attacks on IoT infrastructure

@load tuning/defaults
@load misc/scan
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells

# Protocol analyzers
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/software
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/software
@load protocols/http/software-browser-plugins
@load protocols/mysql/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs

# Security and attack detection
@load policy/frameworks/notice/extend-email/hostnames
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/known-masters-slaves
@load policy/protocols/modbus/track-memmap
@load policy/protocols/ssl/notary

# File analysis
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR

# Custom IoT honeypot detection scripts
@load ./scripts/detect-mirai-scan.zeek
@load ./scripts/http-exploit-detection.zeek
@load ./scripts/ssh-bruteforce-enhanced.zeek

# Network configuration
redef Site::local_nets = {
    172.20.0.0/24,  # Honeypot network
};

# Consider everything outside our network as external
redef Site::private_address_space = {
    172.20.0.0/24,
};

# Log rotation configuration
# Rotate logs every 1 hour to prevent large files
redef Log::default_rotation_interval = 1hr;

# Compress rotated logs to save disk space
redef Log::default_rotation_postprocessor_cmd = "gzip";

# Log file naming with timestamps
redef Log::default_rotation_date_format = "%Y-%m-%d-%H-%M-%S";

# Email configuration for critical alerts (if configured)
# redef Notice::mail_dest = "security@example.com";
# redef Notice::mail_from = "zeek@honeypot.local";
# redef Notice::sendmail = "/usr/sbin/sendmail";

# Notice policy - adjust severity and actions
redef Notice::emailed_types += {
    # SSH attacks
    SSH::Password_Guessing,
    SSHBruteforce::SSH_Bruteforce_Success,

    # HTTP exploits
    HTTPExploit::HTTP_Shellshock_Attempt,
    HTTPExploit::HTTP_SQLi_Attempt,
    HTTPExploit::HTTP_Command_Injection,

    # Mirai detection
    MiraiDetect::Mirai_Scan_Detected,
    MiraiDetect::Mirai_Bruteforce_Detected,

    # Scanning
    Scan::Address_Scan,
    Scan::Port_Scan,
};

# SSH configuration
redef SSH::password_guesses_limit = 10;
redef SSH::guessing_timeout = 10min;

# HTTP configuration
redef HTTP::default_capture_password = T;
redef HTTP::default_capture_cookies = T;

# FTP configuration
redef FTP::default_capture_password = T;

# File extraction configuration
# Extract files seen in HTTP, FTP, and other protocols for analysis
redef FileExtract::prefix = "/opt/zeek/extracted/";
redef FileExtract::default_limit = 10MB;

# Hash all files
redef Files::hash_alg = "sha256";

# Intelligence framework (for known bad IPs, domains, etc.)
@load frameworks/intel/seen
@load frameworks/intel/do_notice

# Configure file extraction for malware analysis
hook FileExtract::extract(f: fa_file, meta: fa_metadata) &priority=5
{
    # Extract executable files
    if (f$info?$mime_type)
    {
        local mime = f$info$mime_type;

        # Extract binaries and scripts
        if (mime == "application/x-executable" ||
            mime == "application/x-sharedlib" ||
            mime == "application/x-dosexec" ||
            mime == "application/x-elf" ||
            /script/ in mime ||
            /shell/ in mime)
        {
            return T;
        }
    }

    # Extract based on file extensions
    if (f$info?$filename)
    {
        local fname = f$info$filename;

        if (/\.(exe|dll|so|sh|py|pl|php|bin|elf|mips|arm|x86)$/i in fname)
        {
            return T;
        }
    }

    return F;
}

# Connection timeout configuration
# Reduce timeouts for honeypot environment (attackers tend to disconnect quickly)
redef tcp_attempt_delay = 5sec;
redef tcp_close_delay = 10sec;
redef tcp_partial_close_delay = 3sec;
redef tcp_reset_delay = 5sec;

# Increase table sizes for high-volume honeypot traffic
redef table_expire_interval = 10min;
redef table_incremental_step = 5000;

# Performance tuning
redef expensive_profiling_multiple = 20;

# Packet filter (optional - adjust based on your needs)
# redef PacketFilter::default_capture_filter = "ip or not ip";

# Notice suppression for known noisy sources
# Add IPs/networks that should be suppressed
# redef Notice::ignored_types += {
#     Scan::Address_Scan,  # If you get too many scan notices
# };

# Logging configuration - enable JSON for easier parsing by Logstash
redef LogAscii::use_json = F;  # Keep TSV format for better compatibility
redef LogAscii::separator = "\t";

# Worker configuration (for cluster deployments)
# @load policy/frameworks/cluster

# DPD (Dynamic Protocol Detection) configuration
# Useful for detecting protocols on non-standard ports
redef dpd_config += {
    [Analyzer::ANALYZER_SSH] = [$ports = { 22/tcp, 2222/tcp }],
    [Analyzer::ANALYZER_TELNET] = [$ports = { 23/tcp, 2323/tcp }],
    [Analyzer::ANALYZER_HTTP] = [$ports = { 80/tcp, 8080/tcp, 8081/tcp, 8888/tcp }],
    [Analyzer::ANALYZER_FTP] = [$ports = { 21/tcp }],
    [Analyzer::ANALYZER_MODBUS] = [$ports = { 502/tcp }],
};

# Signatures - enable if you have custom signature files
# @load-sigs /opt/zeek/signatures/local.sig

# Software version tracking
redef Software::tracking = ALL_HOSTS;

# Geolocation (requires GeoIP database)
# @load policy/protocols/conn/community-id
# redef Conn::community_id_version = 1;

# Custom event handlers

# Log when Zeek starts
event zeek_init()
{
    print "IoT Honeypot Zeek started";
    print fmt("Monitoring network: %s", Site::local_nets);
    print fmt("Log rotation: %s", Log::default_rotation_interval);
    print fmt("Compression: enabled (gzip)");
}

# Log when Zeek stops
event zeek_done()
{
    print "IoT Honeypot Zeek stopped";
}

# Custom log reduction
# Reduce verbosity of certain logs to save disk space
event bro_init() &priority=-5
{
    # Remove overly verbose logs if needed
    # Log::disable_stream(PacketFilter::LOG);
}

# Connection summary for monitoring
global conn_count = 0;
global unique_sources: set[addr] = {};

event connection_established(c: connection)
{
    ++conn_count;
    add unique_sources[c$id$orig_h];
}

# Periodic status report (every 1 hour)
event status_report()
{
    print fmt("Zeek Status: %d connections, %d unique sources",
              conn_count, |unique_sources|);

    # Reset counters
    conn_count = 0;
    clear_table(unique_sources);

    # Schedule next report
    schedule 1hr { status_report() };
}

event zeek_init()
{
    # Start periodic status reporting
    schedule 1hr { status_report() };
}

# Custom notice hook for enhanced logging
hook Notice::policy(n: Notice::Info) &priority=5
{
    # Add hostname if available
    if (n?$src && n$src in Site::local_nets)
    {
        n$note = fmt("%s (local)", n$note);
    }

    # Add geographic info if available
    if (n?$src)
    {
        local loc = lookup_location(n$src);
        if (loc?$country_code)
        {
            n$sub = fmt("%s [%s]", n$sub, loc$country_code);
        }
    }
}

print "Custom IoT Honeypot configuration loaded";
