##! Enhanced SSH brute force detection for IoT honeypot
##! Extends Zeek's built-in SSH analysis with IoT-specific patterns
##!
##! Author: HoneyNetV2 Project
##! MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1078.001 (Default Accounts)

@load base/frameworks/notice
@load base/protocols/ssh
@load policy/protocols/ssh/detect-bruteforcing

module SSHBruteforce;

export {
    redef enum Notice::Type += {
        ## Enhanced SSH brute force detection
        SSH_Bruteforce_Enhanced,
        ## Rapid SSH connection attempts
        SSH_Rapid_Connections,
        ## Known weak credentials attempt
        SSH_Weak_Credentials,
        ## SSH scanning behavior
        SSH_Scanner_Detected,
        ## Successful login after brute force
        SSH_Bruteforce_Success,
    };

    ## Time window for tracking SSH attempts
    const bruteforce_window = 10min &redef;

    ## Threshold for rapid connections
    const rapid_conn_threshold = 15 &redef;

    ## Threshold for failed login attempts
    const failed_login_threshold = 10 &redef;

    ## Common weak usernames targeted by botnets
    const weak_usernames: set[string] = {
        "root", "admin", "user", "test", "guest",
        "pi", "ubuntu", "oracle", "support", "default",
        "user1", "administrator", "Administrator", "daemon",
        "ftp", "postgres", "mysql", "www-data", "nobody",
    } &redef;

    ## Table to track SSH attempts per source IP
    global ssh_conn_attempts: table[addr] of count &create_expire=bruteforce_window &default=0;
    global ssh_failed_logins: table[addr] of count &create_expire=bruteforce_window &default=0;
    global ssh_weak_user_attempts: table[addr] of count &create_expire=bruteforce_window &default=0;
    global ssh_successful_after_fail: table[addr] of bool &create_expire=bruteforce_window &default=F;
}

## Track SSH connection attempts
event ssh_auth_attempted(c: connection, authenticated: bool)
{
    local src = c$id$orig_h;

    # Increment connection counter
    ++ssh_conn_attempts[src];

    # Track failed attempts
    if (!authenticated)
    {
        ++ssh_failed_logins[src];

        # Check if threshold exceeded
        if (ssh_failed_logins[src] >= failed_login_threshold)
        {
            NOTICE([$note=SSH_Bruteforce_Enhanced,
                    $conn=c,
                    $src=src,
                    $msg=fmt("SSH brute force attack from %s (%d failed attempts in %s)",
                            src, ssh_failed_logins[src], bruteforce_window),
                    $identifier=cat(src)]);

            # Mark that this IP has been brute forcing
            ssh_successful_after_fail[src] = T;
        }
    }
    else
    {
        # Successful login
        # Check if this follows failed attempts (compromised account)
        if (ssh_failed_logins[src] > 0)
        {
            NOTICE([$note=SSH_Bruteforce_Success,
                    $conn=c,
                    $src=src,
                    $msg=fmt("Successful SSH login from %s after %d failed attempts",
                            src, ssh_failed_logins[src]),
                    $identifier=cat(src, "-success")]);

            # Reset counter after successful compromise
            ssh_failed_logins[src] = 0;
        }
    }

    # Check for rapid connections
    if (ssh_conn_attempts[src] >= rapid_conn_threshold)
    {
        NOTICE([$note=SSH_Rapid_Connections,
                $conn=c,
                $src=src,
                $msg=fmt("Rapid SSH connections from %s (%d attempts in %s)",
                        src, ssh_conn_attempts[src], bruteforce_window),
                $identifier=cat(src, "-rapid")]);

        # Reset to avoid repeated notices
        ssh_conn_attempts[src] = 0;
    }
}

## Detect SSH scanning behavior
event ssh_server_version(c: connection, version: string)
{
    local src = c$id$orig_h;

    # If connection closes very quickly after server version, likely a scanner
    schedule 3sec {
        if (c$duration < 3sec && !c?$ssh)
        {
            NOTICE([$note=SSH_Scanner_Detected,
                    $conn=c,
                    $src=src,
                    $msg=fmt("SSH scanner detected from %s (quick disconnect after version)", src),
                    $identifier=cat(src, c$start_time)]);
        }
    };
}

## Detect attempts with weak/common usernames
event ssh_auth_result(c: connection, result: string, auth_attempts: count)
{
    # This event is available if SSH logging includes authentication details
    # Extract username if available from SSH analyzer
}

## Custom event for tracking weak credential attempts
## Note: Zeek doesn't expose SSH username by default in events
## This would require custom SSH analyzer modifications or log parsing
event connection_state_remove(c: connection)
{
    # Check if this was an SSH connection
    if (c$id$resp_p == 22/tcp)
    {
        local src = c$id$orig_h;

        # Very short SSH sessions often indicate automated scanning
        if (c$duration < 5sec && c?$ssh)
        {
            # Likely a scanner or failed auth
            ++ssh_conn_attempts[src];
        }
    }
}

## Log enhanced SSH bruteforce events
event zeek_init()
{
    Log::create_stream(SSHBruteforce::LOG,
                      [$columns=record {
                          ts: time &log;
                          src_ip: addr &log;
                          dst_ip: addr &log;
                          dst_port: port &log;
                          detection_type: string &log;
                          conn_attempts: count &log &optional;
                          failed_logins: count &log &optional;
                          authenticated: bool &log &optional;
                          note: string &log &optional;
                      },
                      $path="ssh_bruteforce"]);
}

## Hook into Notice framework to log our detections
hook Notice::policy(n: Notice::Info)
{
    if (n$note in set(SSH_Bruteforce_Enhanced, SSH_Rapid_Connections,
                     SSH_Weak_Credentials, SSH_Scanner_Detected,
                     SSH_Bruteforce_Success))
    {
        if (n?$conn && n?$src)
        {
            local c = n$conn;
            local src = n$src;
            local detection_type = "";

            switch (n$note) {
                case SSH_Bruteforce_Enhanced:
                    detection_type = "bruteforce";
                    break;
                case SSH_Rapid_Connections:
                    detection_type = "rapid_connections";
                    break;
                case SSH_Weak_Credentials:
                    detection_type = "weak_credentials";
                    break;
                case SSH_Scanner_Detected:
                    detection_type = "scanner";
                    break;
                case SSH_Bruteforce_Success:
                    detection_type = "bruteforce_success";
                    break;
            }

            Log::write(SSHBruteforce::LOG, [
                $ts=network_time(),
                $src_ip=src,
                $dst_ip=c$id$resp_h,
                $dst_port=c$id$resp_p,
                $detection_type=detection_type,
                $conn_attempts=ssh_conn_attempts[src],
                $failed_logins=ssh_failed_logins[src],
                $note=n$msg
            ]);
        }
    }
}

## Adjust built-in SSH::Password_Guessing notice to work with our system
redef SSH::password_guesses_limit = 10;
redef SSH::guessing_timeout = 10min;
