import "pe"
import "math"

rule detect_malware {
    meta:
        description = "Detects malware-like behavior in PE files"
    strings:
        $malicious_str = "malware_string" // Placeholder: Replace with a specific malware string or pattern
        $suspicious_api = "CreateProcess" nocase
    condition:
        uint16(0) == 0x5A4D and
        ($malicious_str or $suspicious_api)
}

rule hidden_files_sensitive_data {
    meta:
        description = "Detects hidden files containing sensitive information (e.g., 'confidential', 'password')"
    strings:
        $confidential = "confidential" // Placeholder: Replace with strings specific to RapidoBank's sensitive information
        $password = "password" // Placeholder: Replace with strings specific to RapidoBank's sensitive information
    condition:
        any of ($confidential, $password)
}

rule hidden_files {
    meta:
        description = "Detects filenames starting with '.' (hidden)"
    strings:
        $dot_file = "."
    condition:
        filename matches /^\\.[a-zA-Z0-9_-]+$/
}

rule detect_scripts {
    meta:
        description = "Detects common script files like .js, .vbs, and .ps1"
    condition:
        (uint32(0) == 0x7B5C7274) or // "{\\rt" (indicating .rtf)
        (uint16(0) == 0xEFBB) or     // UTF-8 BOM (indicating plain text files)
        (uint32(0) == 0x50532D31) or // "PS-1" (indicating PowerShell files)
        (uint16(0) == 0x2321)        // Shebang "#!" (indicating script files)
}

rule detect_network_executables {
    meta:
        description = "Detects executables accessing network resources"
    strings:
        $win_net = "ws2_32.dll" // Windows network library
        $linux_net = "connect"  // Linux network system call
    condition:
        pe and ($win_net or $linux_net)
}

rule detect_malicious_urls {
    meta:
        description = "Detects malicious URLs in executables"
    strings:
        $url_regex = /http[s]?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\/%&=\?_\-\.]+/ nocase
    condition:
        uint16(0) == 0x5A4D and $url_regex
}

rule detect_custom_signatures {
    meta:
        description = "Detects custom strings and patterns that might indicate malicious activity"
    strings:
        $custom_str1 = "custom_signature_1" // Placeholder: Replace with specific RapidoBank patterns
        $custom_str2 = { 6A 40 68 00 30 00 00 6A 14 } // Placeholder: Replace with specific hexadecimal pattern
    condition:
        any of them
}

rule suspicious_shell_commands {
    meta:
        description = "Detects suspicious commands often used in malicious shell scripts"
    strings:
        $cmd_sudo = "sudo" nocase
        $cmd_netstat = "netstat" nocase
        $cmd_wget = "wget" nocase
        $cmd_curl = "curl" nocase
        $cmd_iptables = "iptables" nocase
        $cmd_chmod_777 = "chmod 777"
    condition:
        any of ($cmd_sudo, $cmd_netstat, $cmd_wget, $cmd_curl, $cmd_iptables, $cmd_chmod_777)
}

rule common_rootkit_files {
    meta:
        description = "Detects binaries often modified or replaced by rootkits"
    strings:
        $ps = "/bin/ps"
        $top = "/usr/bin/top"
        $ls = "/bin/ls"
        $netstat = "/bin/netstat"
    condition:
        any of them
}

rule detect_webshells {
    meta:
        description = "Detects common webshell patterns"
    strings:
        $php_shell = "<?php" nocase
        $cmd_exec = "system(" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
    condition:
        any of ($php_shell, $cmd_exec, $eval, $exec)
}

rule sensitive_config_files {
    meta:
        description = "Detects sensitive configuration files on a Linux system"
    strings:
        $mysql = "mysql_password" // Placeholder: Replace with sensitive RapidoBank database configurations
        $api_key = "api_key" // Placeholder: Replace with actual API key patterns
        $ssh_key = "-----BEGIN RSA PRIVATE KEY-----"
    condition:
        any of ($mysql, $api_key, $ssh_key)
}

rule detect_altered_linux_commands {
    meta:
        description = "Detects malicious alteration of important Linux system commands"
    strings:
        $bash = "/bin/bash"
        $ls = "/bin/ls"
        $whoami = "/usr/bin/whoami"
        $passwd = "/usr/bin/passwd"
    condition:
        any of them
}

