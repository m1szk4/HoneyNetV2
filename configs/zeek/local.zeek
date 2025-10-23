# HoneyNetV2 Zeek Local Configuration
# This is loaded automatically and will execute site-specific scripts

# Load all standard analysis scripts
@load base/frameworks/software
@load base/frameworks/files
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl

# Load additional policy scripts
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ftp/detect
@load policy/protocols/ftp/software
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/software
@load policy/protocols/smb
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/software
@load policy/protocols/ssl/known-certs
@load policy/protocols/ssl/validate-certs

# Load custom honeypot detection scripts
@load ./scripts/detect-mirai.zeek
@load ./scripts/detect-iot-attacks.zeek
@load ./scripts/track-downloads.zeek
@load ./scripts/detect-crypto-mining.zeek

# Network configuration for honeypot environment
redef Site::local_nets = { 172.20.0.0/24 };

# SSH brute force detection tuning for honeypot
redef SSH::password_guesses_limit = 5;
redef SSH::guessing_timeout = 10 mins;

# HTTP detection settings
redef HTTP::default_capture_password = T;
redef HTTP::default_max_header_length = 8192;

# File extraction settings
redef HTTP::default_file_extraction_limit = 10485760;  # 10 MB

# FTP settings
redef FTP::default_capture_password = T;

# Software version detection
redef Software::tracked_types += {
    HTTP::SERVER,
    HTTP::BROWSER_PLUGIN,
    SSH::SERVER,
    SSH::CLIENT,
    FTP::SERVER,
    DNS::SERVER,
    SMTP::MAIL_CLIENT,
    SMTP::MAIL_SERVER,
};

# Logging configuration
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_postprocessor_cmd = "gzip";

# Notice framework
redef Notice::mail_dest = "";  # Disabled for honeypot
redef Notice::mail_subject_prefix = "[HoneyNet]";

# Connection tracking
redef Conn::default_log_records = T;

# Known hosts/services tracking
redef Known::host_tracking = ALL_HOSTS;
redef Known::service_tracking = ALL_SERVICES;

# Expire known items after 1 day (adjust as needed)
redef Known::host_expire_interval = 1 day;
redef Known::service_expire_interval = 1 day;
