# File Download Tracking Script for Zeek
# Tracks and logs all file downloads in the honeypot environment

@load base/protocols/http
@load base/protocols/ftp
@load base/frameworks/files
@load base/frameworks/notice

module DownloadTracker;

export {
    redef enum Notice::Type += {
        Malware_Download_Detected,
        Suspicious_File_Download,
        Script_Download,
        Binary_Download,
    };

    # Suspicious file extensions
    const suspicious_extensions = /\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.ps1|\.sh|\.elf|\.bin|\.mips|\.arm|\.x86/ &redef;

    # Script file extensions
    const script_extensions = /\.sh|\.bash|\.py|\.pl|\.php|\.jsp|\.asp/ &redef;

    # Log structure for downloads
    type DownloadInfo: record {
        ts: time &log;
        source_ip: addr &log;
        dest_ip: addr &log;
        method: string &log &optional;
        url: string &log &optional;
        filename: string &log &optional;
        mime_type: string &log &optional;
        file_size: count &log &optional;
        md5: string &log &optional;
        sha1: string &log &optional;
        sha256: string &log &optional;
    };

    global download_log: event(rec: DownloadInfo);
}

# Create custom log stream
event zeek_init() {
    Log::create_stream(DownloadTracker::DOWNLOAD_LOG,
        [$columns=DownloadInfo,
         $path="honeypot-downloads"]);
}

# Track HTTP downloads
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if (!is_orig) {  # Response from server
        # File being downloaded
    }
}

# Track file over HTTP
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) {
    if (f?$http && f$http?$uri) {
        local info: DownloadInfo;
        info$ts = network_time();
        info$source_ip = c$id$orig_h;
        info$dest_ip = c$id$resp_h;
        info$url = f$http$uri;

        if (f?$info && f$info?$filename)
            info$filename = f$info$filename;

        if (f?$info && f$info?$mime_type)
            info$mime_type = f$info$mime_type;

        Log::write(DownloadTracker::DOWNLOAD_LOG, info);

        # Check for suspicious files
        if (f$info?$filename && suspicious_extensions in f$info$filename) {
            NOTICE([$note=Malware_Download_Detected,
                    $msg=fmt("Malware download detected: %s from %s", f$info$filename, c$id$orig_h),
                    $conn=c]);
        }
    }
}

# Track file hashes
event file_hash(f: fa_file, kind: string, hash: string) {
    # Log file hashes for later analysis and threat intelligence correlation
}

# Track FTP downloads
event ftp_request(c: connection, command: string, arg: string) {
    if (command == "RETR") {
        NOTICE([$note=Binary_Download,
                $msg=fmt("FTP file download: %s from %s", arg, c$id$orig_h),
                $conn=c]);
    }
}

# Track wget/curl commands in captured sessions
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (method == "GET" && (suspicious_extensions in original_URI || script_extensions in original_URI)) {
        NOTICE([$note=Suspicious_File_Download,
                $msg=fmt("Suspicious file requested: %s from %s", original_URI, c$id$orig_h),
                $conn=c]);
    }
}
