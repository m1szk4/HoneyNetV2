# IoT Attack Detection Script for Zeek
# Detects various IoT-specific attack patterns

@load base/protocols/conn
@load base/frameworks/notice

module IoTAttacks;

export {
    redef enum Notice::Type += {
        IoT_Default_Credentials,
        IoT_Exploit_Attempt,
        IoT_Port_Scan,
        IoT_Device_Enumeration,
        UPNP_Abuse,
    };

    # Common IoT device ports
    const iot_ports = set(81/tcp, 554/tcp, 8080/tcp, 8081/tcp, 8000/tcp, 8443/tcp, 9000/tcp) &redef;

    # IoT device fingerprinting patterns
    const iot_user_agents = /DVR|IPCamera|DNVRS|NETSurveillance|Hikvision|Dahua/ &redef;
}

# Track connections to common IoT ports
global iot_scanners: table[addr] of count &create_expire=1 min &default=0;

event connection_established(c: connection) {
    if (c$id$resp_p in iot_ports) {
        local src = c$id$orig_h;
        if (src !in iot_scanners)
            iot_scanners[src] = 0;

        iot_scanners[src] += 1;

        if (iot_scanners[src] > 5) {
            NOTICE([$note=IoT_Port_Scan,
                    $msg=fmt("IoT port scanning detected from %s", src),
                    $conn=c]);
        }
    }
}

# Detect IoT device enumeration via HTTP
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # Detect attempts to access common IoT device paths
    if (/\/cgi-bin\/|\/web\/|\/admin\/|\/config\/|\/system\/|\/setup.cgi|\/goform\// in original_URI) {
        NOTICE([$note=IoT_Device_Enumeration,
                $msg=fmt("IoT device path enumeration: %s from %s", original_URI, c$id$orig_h),
                $conn=c]);
    }
}

# Detect IoT-specific user agents
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "USER-AGENT" && iot_user_agents in value) {
        NOTICE([$note=IoT_Device_Enumeration,
                $msg=fmt("IoT device user agent detected: %s from %s", value, c$id$orig_h),
                $conn=c]);
    }
}

# Detect UPnP exploitation attempts
event udp_request(c: connection) {
    if (c$id$resp_p == 1900/udp) {
        # UPnP Simple Service Discovery Protocol
        # Monitor for abuse patterns
    }
}

# Detect RTSP (camera streaming protocol) attacks
event connection_established(c: connection) {
    if (c$id$resp_p == 554/tcp) {
        # RTSP port - commonly targeted for IP camera attacks
        NOTICE([$note=IoT_Exploit_Attempt,
                $msg=fmt("RTSP connection attempt from %s", c$id$orig_h),
                $conn=c]);
    }
}
