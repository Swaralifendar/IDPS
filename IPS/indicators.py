INDICATORS = {
# --------------------------------------------------
# IP REPUTATION
# --------------------------------------------------

"malicious_ips": {
    # Documented malicious infrastructure from CISA advisories
    "104.223.34.198",
    "92.222.241.76",
    "109.248.150.13",
    "104.155.149.103",
},

"c2_ips": {
    # CISA/FBI documented Conti Cobalt Strike infrastructure
    "162.244.80.235",
    "85.93.88.165",
    "185.141.63.120",
    "82.118.21.1",
},

"scanner_ips": {
    # Keep empty until you populate this from a trusted
    # scanner/reputation feed or your own observed IOCs.
},


# --------------------------------------------------
# MALWARE / PAYLOAD
# --------------------------------------------------

"malicious_payload_signatures": {
    # High-confidence strings associated with malware
    # / malware delivery. Used by BLOCK rules 330005
    # (NIDS 100025) and 330007 (NIDS 100030).
    #
    # "cmd.exe /c" and "${jndi:" are intentionally not
    # here: "cmd.exe /c" appears in legitimate scripts
    # downloaded over HTTP, and Log4j has its own list.
    "powershell -enc ",
    "powershell -encodedcommand",
    "powershell.exe -enc ",
    "powershell.exe -encodedcommand",
    "/bin/sh -i",
    "/bin/bash -i",
},

"malware_hashes": {
    # WannaCry samples documented in malware-analysis
    # sources.

    # WannaCry sample
    "32f24601153be0885f11d62e0a8a2f0280a2034fc981d8184180c5d3b1b9e8cf",

    # WannaCry encryptor sample
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",

    # WannaCry @WanaDecryptor@ sample
    "b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25",

    # WannaCry taskdl sample
    "4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79",

    # WannaCry taskse sample
    "2ca2d550e603d74dedda03156023135b38da3630cb014e3d00b1263358c5f00d",
},
    # --------------------------------------------------
    # EXPLOIT
    # --------------------------------------------------

    "high_confidence_sqli_signatures": {
        "UNION SELECT",
        "UNION ALL SELECT",
        "UNION+SELECT",
        "UNION+ALL+SELECT",
        "UNION%20SELECT",
        "UNION%20ALL%20SELECT",
        "UNION/**/SELECT",
    },

    "xss_signatures": {
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
    },

    # Used by BLOCK rule 330008. Only lookups with a
    # remote protocol; the bare "${jndi:" prefix is what
    # the NIDS rule already matches.
    "log4j_signatures": {
        "${jndi:ldap:",
        "${jndi:ldaps:",
        "${jndi:rmi:",
        "${jndi:dns:",
        "${jndi:iiop:",
        "${jndi:corba:",
        "${jndi:nds:",
        "${jndi:nis:",
        "${jndi:http:",
    },

    "path_traversal_signatures": {
        "../",
        "..\\",
    },

    "command_injection_signatures": {
        "cmd.exe /c",
        "powershell -",
        "/bin/sh",
        "/bin/bash",
    },


    # --------------------------------------------------
    # C2 / REVERSE SHELL
    # --------------------------------------------------

    "reverse_shell_signatures": {
        "nc -e",
        "ncat -e",
        "bash -i",
        "cmd.exe /c",
    },

    "c2_payload_signatures": {
        # high-confidence C2 strings
    },

    "webshell_signatures": {
        "cmd=",
        "powershell -",
        "shell_exec(",
    },

      # --------------------------------------------------
    # 100041 - WannaCry Kill Switch
    # --------------------------------------------------
    #
    # This is a strong static indicator because the
    # WannaCry sample contacted a specific kill-switch
    # domain.
    #
    # DNS packets encode names as length-prefixed labels
    # (\x29iuqerf...gwea\x03com), so the ".com" form never
    # appears in the payload. Only the label is matched.
    #
    "wannacry_killswitch_signatures": {
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea",
        "iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea",
        "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea",
    },


    # --------------------------------------------------
    # 100044 - ICMP Covert Channel
    # --------------------------------------------------
    #
    # Do NOT use generic strings such as "ICMP",
    # "DNS", or "HTTP" here.
    #
    # These are recognizable content indicators
    # reported in research on ICMP covert channels.
    #
    # Short strings such as "dns" occur by chance in
    # binary ICMP payloads and were removed.
    #
    "icmp_covert_channel_signatures": {
        "http://",
        "https://",
        "HTTP/1.1",
        "Host: ",
    },


    # --------------------------------------------------
    # 100050 - DNS Tunneling
    # --------------------------------------------------
    #
    # These are tool/protocol-specific strings that can
    # occur in DNS tunneling traffic. They are NOT by
    # themselves proof of tunneling.
    #
    "dns_tunneling_signatures": {
        "dnscat",
        "dnscat2",
        "iodine",
    },


    # --------------------------------------------------
    # 100056 - SSDP Amplification
    # --------------------------------------------------
    #
    # SSDP amplification commonly uses an M-SEARCH
    # request with ssdp:discover / ssdp:all.
    #
    "ssdp_amplification_signatures": {
        "M-SEARCH * HTTP/1.1",
        "ssdp:discover",
        "ST: ssdp:all",
        "239.255.255.250:1900",
    },

    # --------------------------------------------------
    # HIDS - HOST VALIDATION INDICATORS
    # --------------------------------------------------

    "sensitive_privilege_signatures": {
        "sedebugprivilege",
        "setakeownershipprivilege",
        "seloaddriverprivilege",
        "seimpersonateprivilege",
        "sebackupprivilege",
        "serestoreprivilege",
        "setcbprivilege",
    },

    "administrative_group_signatures": {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "remote desktop users",
        "backup operators",
        "account operators",
    },

    "suspicious_process_signatures": {
        "vssadmin",
        "delete shadows",
        "wmic",
        "shadowcopy",
        "wbadmin",
        "certutil",
        "whoami",
        "nltest",
        "mimikatz",
        "sekurlsa",
        "lsadump",
        "procdump",
        # "psexec" removed: widely used by administrators.
        "regsvr32",
        "rundll32",
    },

    "suspicious_powershell_signatures": {
        "downloadstring",
        "downloadfile",
        "net.webclient",
        "invoke-expression",
        "iex",
        "-encodedcommand",
        "-enc",
        "executionpolicy bypass",
        "amsiutils",
        "amsiinitfailed",
        "reflection.assembly]::load",
        "minidumpwritedump",
    },

    "suspicious_service_signatures": {
        "cmd.exe",
        "powershell",
        "rundll32",
        ".bat",
        ".cmd",
        ".ps1",
        "\\temp\\",
        "\\appdata\\",
        "\\users\\",
    },

    # HIDS reports the service display name (param1) for
    # 7031/7034/7024, so display names are listed too.
    # "sense" removed: too short for substring matching.
    "critical_security_services": {
        "windefend",
        "microsoft defender antivirus",
        "windows defender antivirus",
        "windows defender advanced threat protection",
        "mpssvc",
        "windows defender firewall",
        "eventlog",
        "windows event log",
        "sysmon",
    },

    "suspicious_scheduled_task_signatures": {
        "powershell",
        "cmd.exe",
        "rundll32",
        "wscript",
        "cscript",
        ".bat",
        ".vbs",
        "\\temp\\",
        "\\appdata\\",
    },

    "sensitive_account_signatures": {
        "administrator",
        "admin",
        "guest",
        "krbtgt",
        "defaultaccount",
    },

}


def get_indicator_list(name):
    return INDICATORS.get(name, set())
