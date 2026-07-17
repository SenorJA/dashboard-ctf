# ── kali-mcp adapted for M.I.R.V. ─────────────────────────
# Lightweight Kali container with 50+ security tools.
# MIRV executes commands via docker exec (no MCP server needed).
# ────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # --- Core Utilities ---
    curl \
    wget \
    net-tools \
    iputils-ping \
    perl \
    libnet-ssleay-perl \
    dnsutils \
    whois \
    # --- Port Scanning & Network Discovery ---
    nmap \
    masscan \
    arp-scan \
    netcat-traditional \
    # --- OSINT & Reconnaissance ---
    whatweb \
    theharvester \
    fierce \
    dnsrecon \
    amass \
    sublist3r \
    wafw00f \
    # --- Web Application Testing ---
    gobuster \
    dirb \
    nikto \
    ffuf \
    wfuzz \
    commix \
    arjun \
    nuclei \
    wpscan \
    # --- Network & AD Pentesting ---
    enum4linux \
    crackmapexec \
    smbclient \
    impacket-scripts \
    responder \
    snmp \
    tcpdump \
    tshark \
    # --- Exploitation ---
    sqlmap \
    hydra \
    exploitdb \
    # --- Password & Hash Cracking ---
    john \
    hashcat \
    hash-identifier \
    cewl \
    crunch \
    # --- Forensics & Reverse Engineering ---
    binwalk \
    foremost \
    steghide \
    libimage-exiftool-perl \
    # --- Wordlists ---
    seclists \
    wordlists \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Decompress rockyou
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip -k /usr/share/wordlists/rockyou.txt.gz; \
    fi

# Refresh exploit/vuln databases
RUN searchsploit -u || true && \
    nuclei -update-templates || true

# Simple HTTP health endpoint
RUN apt-get install -y openssh-server && \
    mkdir -p /var/run/sshd && \
    echo "root:mirv" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    apt-get clean

RUN mkdir -p /tmp/workspace
WORKDIR /tmp/workspace

EXPOSE 22

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD sshd -t || exit 1

CMD ["/usr/sbin/sshd", "-D", "-e"]
