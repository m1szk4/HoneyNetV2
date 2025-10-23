# Mirai Botnet Detection Script for Zeek
# Detects Mirai-specific patterns and behaviors

@load base/protocols/conn
@load base/frameworks/notice

module Mirai;

export {
    redef enum Notice::Type += {
        Mirai_Scanner_Detected,
        Mirai_Login_Attempt,
        Mirai_Command_Detected,
        Mirai_Download_Attempt,
    };

    # Known Mirai command patterns
    const mirai_commands = /bin\/busybox|ECCHI|TSource|wget.*\/bins\/|tftp.*-g.*-r/ &redef;

    # Known Mirai credential combinations
    const mirai_users = set("root", "admin", "user", "support", "ubnt") &redef;
    const mirai_passwords = set("root", "admin", "xc3511", "vizxv", "888888", "xmhdipc", "default", "juantech", "123456") &redef;
}

# Detect Mirai scanner by rapid connection attempts
event connection_state_remove(c: connection) {
    if (c$id$resp_p == 23/tcp || c$id$resp_p == 2323/tcp) {
        if (c$duration < 2 secs) {
            local src = c$id$orig_h;
            # Track short-lived telnet connections (typical scanner behavior)
            NOTICE([$note=Mirai_Scanner_Detected,
                    $msg=fmt("Potential Mirai scanner detected from %s", src),
                    $conn=c,
                    $identifier=cat(src)]);
        }
    }
}

# Detect Mirai login attempts via Telnet
event telnet_authentication_successful(c: connection, user: string, password: string) {
    if (user in mirai_users && password in mirai_passwords) {
        NOTICE([$note=Mirai_Login_Attempt,
                $msg=fmt("Mirai credential attempt: %s:%s from %s", user, password, c$id$orig_h),
                $conn=c]);
    }
}

# Detect Mirai commands in SSH sessions
event ssh_auth_successful(c: connection, auth_method: string, user: string) {
    # Monitor for post-auth activity that matches Mirai patterns
}

# Detect Mirai download attempts
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (/\/bins\/|\.sh|\.bot|mirai/ in original_URI) {
        NOTICE([$note=Mirai_Download_Attempt,
                $msg=fmt("Potential Mirai binary download: %s from %s", original_URI, c$id$orig_h),
                $conn=c]);
    }
}

# Detect busybox commands (Mirai signature)
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) {
    # This would require deeper packet inspection
}
