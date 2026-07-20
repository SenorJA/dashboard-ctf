"""
VulnForge KnowledgeBase - CVE & MITRE ATT&CK embedded data.
No external dependencies. ~80 entries covering common pentest CVEs + MITRE techniques.
"""

CVE_DB = [
    # -- Web / API --
    {"id": "CVE-2017-0144", "type": "cve", "cvss": 9.3, "description": "EternalBlue - SMBv1 remote code execution (MS17-010). Used by WannaCry.",
     "affected": "Windows Vista/7/8.1/10, Server 2008/2012/2016", "exploit_available": True, "tools": ["metasploit", "impacket"]},
    {"id": "CVE-2021-41773", "type": "cve", "cvss": 7.5, "description": "Apache HTTP Server 2.4.49 - path traversal / RCE via percent-encoded paths.",
     "affected": "Apache 2.4.49", "exploit_available": True, "tools": ["curl", "metasploit"]},
    {"id": "CVE-2021-44228", "type": "cve", "cvss": 10.0, "description": "Log4Shell - Apache Log4j JNDI injection remote code execution.",
     "affected": "Log4j 2.0-2.14.1", "exploit_available": True, "tools": ["metasploit", "nmap", "burpsuite"]},
    {"id": "CVE-2022-22965", "type": "cve", "cvss": 9.8, "description": "Spring4Shell - Spring Framework RCE via data binding.",
     "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19", "exploit_available": True, "tools": ["curl", "metasploit"]},

    # -- SMB / Windows --
    {"id": "CVE-2020-0796", "type": "cve", "cvss": 10.0, "description": "SMBGhost - SMBv3.1.1 compression RCE (SIGRed).",
     "affected": "Windows 10 v1903/1909, Server 1903/1909", "exploit_available": True, "tools": ["metasploit", "impacket"]},
    {"id": "CVE-2019-0708", "type": "cve", "cvss": 9.8, "description": "BlueKeep - RDP remote code execution (pre-auth).",
     "affected": "Windows 7/2008 R2/2008/XP", "exploit_available": True, "tools": ["metasploit"]},
    {"id": "CVE-2017-7494", "type": "cve", "cvss": 7.5, "description": "SambaCry - Samba remote code execution via symlinks.",
     "affected": "Samba 3.5.0-4.6.4", "exploit_available": True, "tools": ["metasploit", "smbclient"]},

    # -- SSH / Auth --
    {"id": "CVE-2018-15473", "type": "cve", "cvss": 5.0, "description": "OpenSSH user enumeration via timing attack (pre-auth).",
     "affected": "OpenSSH 2.2-7.7", "exploit_available": True, "tools": ["nmap", "hydra"]},
    {"id": "CVE-2024-6387", "type": "cve", "cvss": 8.1, "description": "regreSSHion - OpenSSH signal handler race condition RCE (glibc).",
     "affected": "OpenSSH 8.5p1-9.7p1 (glibc)", "exploit_available": False, "tools": ["nmap"]},

    # -- SUDO / Linux PrivEsc --
    {"id": "CVE-2021-3156", "type": "cve", "cvss": 7.8, "description": "Baron Samedit - sudo heap overflow privilege escalation.",
     "affected": "sudo 1.8.2-1.8.31p2", "exploit_available": True, "tools": ["metasploit", "searchsploit"]},
    {"id": "CVE-2023-2640", "type": "cve", "cvss": 7.8, "description": "Ubuntu Kernel - overlayfs privilege escalation (GameOverlay).",
     "affected": "Ubuntu (multiple versions)", "exploit_available": True, "tools": ["searchsploit"]},
    {"id": "CVE-2021-4034", "type": "cve", "cvss": 7.8, "description": "PwnKit - pkexec local privilege escalation.",
     "affected": "polkit 0.105-0.119", "exploit_available": True, "tools": ["searchsploit"]},

    # -- WebApp --
    {"id": "CVE-2019-15107", "type": "cve", "cvss": 9.8, "description": "Webmin - RCE via password_change.cgi (backdoor).",
     "affected": "Webmin < 1.930", "exploit_available": True, "tools": ["metasploit", "curl"]},
    {"id": "CVE-2018-7600", "type": "cve", "cvss": 9.8, "description": "Drupalgeddon2 - Drupal core RCE.",
     "affected": "Drupal 7.x / 8.x", "exploit_available": True, "tools": ["metasploit", "curl"]},
    {"id": "CVE-2017-10271", "type": "cve", "cvss": 7.5, "description": "Oracle WebLogic - XMLDecoder RCE.",
     "affected": "WebLogic 10.3.6, 12.1.3, 12.2.1", "exploit_available": True, "tools": ["metasploit", "curl"]},

    # -- Networks --
    {"id": "CVE-2014-0160", "type": "cve", "cvss": 5.0, "description": "Heartbleed - OpenSSL TLS heartbeat memory leak.",
     "affected": "OpenSSL 1.0.1-1.0.1f", "exploit_available": True, "tools": ["nmap", "metasploit", "sslscan"]},
    {"id": "CVE-2014-3566", "type": "cve", "cvss": 4.3, "description": "POODLE - SSLv3 CBC padding oracle.",
     "affected": "SSLv3", "exploit_available": True, "tools": ["nmap", "sslscan"]},
    {"id": "CVE-2016-0800", "type": "cve", "cvss": 3.1, "description": "DROWN - SSLv2 cross-protocol attack on RSA keys.",
     "affected": "TLS + SSLv2 same key", "exploit_available": True, "tools": ["nmap", "sslscan"]},

    # -- Additional CVEs --
    {"id": "CVE-2022-30190", "type": "cve", "cvss": 7.8, "description": "Follina - MS Office MSDT remote code execution via Word doc.",
     "affected": "Windows + Office", "exploit_available": True, "tools": ["metasploit"]},
    {"id": "CVE-2023-23397", "type": "cve", "cvss": 9.8, "description": "Microsoft Outlook elevation of privilege via MAPI (no user interaction).",
     "affected": "Outlook for Windows", "exploit_available": True, "tools": ["metasploit"]},
    {"id": "CVE-2022-26134", "type": "cve", "cvss": 9.8, "description": "Atlassian Confluence OGNL injection RCE.",
     "affected": "Confluence 1.3.0-7.18.1", "exploit_available": True, "tools": ["curl", "metasploit"]},
    {"id": "CVE-2023-32784", "type": "cve", "cvss": 5.5, "description": "KeePass - master password discovered via memory dump / DPAPI.",
     "affected": "KeePass 2.x", "exploit_available": True, "tools": ["keepass-dump"]},
    {"id": "CVE-2020-1472", "type": "cve", "cvss": 10.0, "description": "Zerologon - Netlogon crypto flaw, domain controller takeover.",
     "affected": "Windows Server 2008-2019", "exploit_available": True, "tools": ["impacket", "metasploit"]},
]

MITRE_DB = [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001 Initial Access",
     "description": "Exploiting a vulnerability in an internet-facing application to gain access.",
     "detection": "IDS/IPS, WAF logs, application logs", "examples": ["Log4Shell", "Heartbleed"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "TA0001 Initial Access / TA0003 Persistence",
     "description": "Using compromised credentials (passwords, keys, tokens) to access systems.",
     "detection": "Authentication logs, UEBA", "examples": ["Default creds", "Password spraying"]},
    {"id": "T1110", "name": "Brute Force", "tactic": "TA0006 Credential Access",
     "description": "Guessing or cracking passwords, hashes, or PINs via repeated attempts.",
     "detection": "Failed login monitoring, account lockout events", "examples": ["Hydra", "John", "Hashcat"]},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "TA0007 Discovery",
     "description": "Scanning for open ports and running services on remote hosts.",
     "detection": "Port scan alerts, netflow analysis", "examples": ["Nmap", "Masscan"]},
    {"id": "T1135", "name": "Network Share Discovery", "tactic": "TA0007 Discovery",
     "description": "Finding mapped drives and network shares on a system.",
     "detection": "Sysmon EID 1, Windows Event 5140", "examples": ["net share", "smbclient"]},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "TA0007 Discovery",
     "description": "Gathering OS, hardware, and software details from a compromised host.",
     "detection": "Command-line monitoring", "examples": ["uname -a", "systeminfo"]},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007 Discovery",
     "description": "Enumerating files and directories on the target.",
     "detection": "File system auditing", "examples": ["ls -la", "dir /s"]},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002 Execution",
     "description": "Using shell interpreters (bash, cmd, PowerShell) to execute commands.",
     "detection": "Process creation events", "examples": ["Reverse shell", "PowerShell Empire"]},
    {"id": "T1059.001", "name": "PowerShell", "tactic": "TA0002 Execution",
     "description": "Malicious use of PowerShell for execution and evasion.",
     "detection": "Script block logging, EID 4104", "examples": ["PowerView", "Nishang"]},
    {"id": "T1505.003", "name": "Web Shell", "tactic": "TA0003 Persistence",
     "description": "Uploading a script to a web server for persistent remote access.",
     "detection": "File integrity monitoring, WAF", "examples": ["p0wny shell", "b374k"]},
    {"id": "T1021.006", "name": "Windows Remote Management (WinRM)", "tactic": "TA0008 Lateral Movement",
     "description": "Using WinRM (5985/5986) for remote administration / lateral movement.",
     "detection": "WinRM event logs, EID 91/168", "examples": ["Evil-WinRM", "winrs"]},
    {"id": "T1021.001", "name": "Remote Desktop Protocol (RDP)", "tactic": "TA0008 Lateral Movement",
     "description": "Using RDP for remote access and lateral movement.",
     "detection": "RDP event logs, EID 4624/4778", "examples": ["xfreerdp", "rdesktop"]},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "TA0008 Lateral Movement",
     "description": "Transferring tools to other systems in the network.",
     "detection": "File share logs, SMB traffic", "examples": ["smbclient", "impacket-smbexec"]},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "TA0003 Persistence / TA0004 Privilege Escalation",
     "description": "Creating or modifying accounts for persistence.",
     "detection": "User account change events", "examples": ["net user", "usermod"]},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004 Privilege Escalation",
     "description": "Using a local vulnerability to elevate privileges.",
     "detection": "Vulnerability scanner, kernel audit", "examples": ["PwnKit", "DirtyPipe", "SUID exploits"]},
    {"id": "T1548.002", "name": "Bypass User Account Control (UAC)", "tactic": "TA0004 Privilege Escalation",
     "description": "Bypassing Windows UAC to execute with admin privileges.",
     "detection": "Event 4688, Sysmon EID 1 (auto-elevation)", "examples": ["UACME", "Fodhelper"]},
    {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "TA0006 Credential Access",
     "description": "Extracting credentials from password managers (KeePass, browser stores).",
     "detection": "Process access events, EID 4663", "examples": ["KeePass extraction", "Browser credential dumping"]},
    {"id": "T1555.003", "name": "Credentials from Web Browsers", "tactic": "TA0006 Credential Access",
     "description": "Dumping saved passwords from Chrome, Firefox, Edge.",
     "detection": "File access events, process monitoring", "examples": ["LaZagne", "Get-ChromePass"]},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "TA0006 Credential Access",
     "description": "Dumping credential material from Windows (LSASS, SAM, NTDS).",
     "detection": "Sysmon EID 10 (lsass process access)", "examples": ["Mimikatz", "Impacket-secretsdump"]},
    {"id": "T1003.001", "name": "LSASS Memory", "tactic": "TA0006 Credential Access",
     "description": "Dumping credentials from LSASS process memory.",
     "detection": "Sysmon EID 10/8, EID 4663", "examples": ["Mimikatz sekurlsa", "procdump"]},
    {"id": "T1558.003", "name": "Kerberos TGS (Silver Ticket)", "tactic": "TA0006 Credential Access",
     "description": "Forging a Kerberos TGS ticket for service access.",
     "detection": "Kerberos event logs (EID 4769 anomalies)", "examples": ["Mimikatz kerberos::golden"]},
    {"id": "T1562", "name": "Impair Defenses", "tactic": "TA0005 Defense Evasion",
     "description": "Disabling security tools, logging, or AV/EDR.",
     "detection": "Service stop events, EID 7036", "examples": ["Disable Defender", "Stop WinDefend"]},
    {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "TA0005 Defense Evasion",
     "description": "Disabling AV/EDR services and processes.",
     "detection": "Service stop events, process termination", "examples": ["net stop windefend", "sc config"]},
    {"id": "T1564", "name": "Hide Artifacts", "tactic": "TA0005 Defense Evasion",
     "description": "Hiding files, processes, or registry keys to evade detection.",
     "detection": "File system audits, alternate data streams", "examples": ["Hidden files", "NTFS ADS"]},
    {"id": "T1574.002", "name": "DLL Side-Loading", "tactic": "TA0005 Defense Evasion / TA0004 Privilege Escalation",
     "description": "Loading a malicious DLL by exploiting the DLL search order.",
     "detection": "Sysmon EID 7 (DLL loaded)", "examples": ["MSBuild side-loading"]},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010 Exfiltration",
     "description": "Exfiltrating data via the existing command and control channel.",
     "detection": "Network data volume anomalies", "examples": ["DNS tunneling", "HTTPS exfil"]},
    {"id": "T1219", "name": "Remote Access Software", "tactic": "TA0011 Command and Control",
     "description": "Using legitimate remote admin tools for C2.",
     "detection": "Network signatures, app whitelisting", "examples": ["AnyDesk", "TeamViewer"]},
    {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "TA0011 Command and Control",
     "description": "Using raw TCP/UDP/ICMP for C2 to evade L7 detection.",
     "detection": "Protocol analysis, netflow anomalies", "examples": ["ICMP shell", "DNS tunneling"]},
    {"id": "T1573", "name": "Encrypted Channel", "tactic": "TA0011 Command and Control",
     "description": "Using encrypted protocols (TLS, HTTPS) for C2.",
     "detection": "JA3 fingerprinting, certificate anomalies", "examples": ["Cobalt Strike HTTPS"]},
    {"id": "T1204", "name": "User Execution", "tactic": "TA0002 Execution",
     "description": "Tricking the user into executing a malicious file.",
     "detection": "Sysmon EID 1, EID 4688", "examples": ["Phishing attachment", "Macro execution"]},
]

# -- Functions --

def search_cve(query: str = "") -> list:
    """Search CVEs by keyword (id, description, affected, tools)."""
    q = (query or "").lower().strip()
    if not q:
        return CVE_DB[:20]  # Return first 20 when no query
    results = []
    for cve in CVE_DB:
        if (q in cve["id"].lower() or
            q in cve["description"].lower() or
            q in cve["affected"].lower() or
            any(q in t for t in cve["tools"])):
            results.append(cve)
    return results

def search_mitre(query: str = "") -> list:
    """Search MITRE ATT&CK by keyword (id, name, tactic, description)."""
    q = (query or "").lower().strip()
    if not q:
        return MITRE_DB[:20]
    results = []
    for tech in MITRE_DB:
        if (q in tech["id"].lower() or
            q in tech["name"].lower() or
            q in tech["tactic"].lower() or
            q in tech["description"].lower()):
            results.append(tech)
    return results

def search_all(query: str = "") -> dict:
    """Search both databases, return combined results."""
    return {
        "cves": search_cve(query),
        "mitre": search_mitre(query),
    }

def get_cve(cve_id: str) -> dict | None:
    """Get a single CVE by exact ID."""
    for cve in CVE_DB:
        if cve["id"].lower() == cve_id.lower():
            return cve
    return None

def get_mitre(tech_id: str) -> dict | None:
    """Get a single MITRE technique by exact ID."""
    for tech in MITRE_DB:
        if tech["id"].lower() == tech_id.lower():
            return tech
    return None
