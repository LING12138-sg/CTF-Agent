# CTF Agent Sandbox — Kali Linux 安全工具镜像
# =============================================
# 基于 CHYing-agent 的 Dockerfile，精简掉 Ghidra/Chrome/VNC 等不需要的组件
# Build: docker build -t ctf-agent-sandbox docker/

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# ============================================================
# Phase 1: Mirror Setup + Base System
# ============================================================
RUN set -eux; \
    mirrors="mirrors.aliyun.com/kali mirrors.cloud.tencent.com/kali mirrors.tencent.com/kali ftp.acc.umu.se/mirror/kali.org/kali mirror.math.princeton.edu/pub/kali"; \
    success=0; \
    for mirror in $mirrors; do \
        echo "deb http://$mirror kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        if apt-get update; then \
            echo "Using Kali mirror: $mirror"; \
            success=1; \
            break; \
        fi; \
    done; \
    if [ "$success" -ne 1 ]; then \
        echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        apt-get update; \
    fi; \
    apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python-is-python3 python3-dev \
    openjdk-21-jdk \
    build-essential gcc g++ make cmake \
    libgmp-dev libmpfr-dev libmpc-dev \
    curl git perl gnupg2 wget sudo jq unzip tree file xxd \
    libnet-ssleay-perl libio-socket-ssl-perl libcrypt-ssleay-perl libssl-dev ca-certificates \
    iputils-ping dnsutils iproute2 net-tools traceroute \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# ============================================================
# Phase 2: Security Tools + Web Fuzzing
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap sqlmap netcat-traditional tcpdump \
    whatweb nuclei \
    smbclient smbmap python3-impacket \
    socat proxychains4 sslscan seclists \
    hydra hashid \
    libimage-exiftool-perl cewl \
    subfinder \
    ffuf arjun wpscan \
    commix \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Web-Fuzzing-Box dictionaries
RUN git clone --depth=1 https://github.com/gh0stkey/Web-Fuzzing-Box.git /usr/share/wordlists/Web-Fuzzing-Box 2>/dev/null || true \
    && rm -rf /usr/share/wordlists/Web-Fuzzing-Box/.git 2>/dev/null || true

# ============================================================
# Phase 3: CTF Tools (Forensics + PWN + Red Team)
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk foremost sleuthkit \
    p7zip-full unrar fcrackzip \
    steghide pngcheck imagemagick \
    sox libsox-fmt-all ffmpeg \
    tshark \
    john hashcat \
    hexedit \
    ruby ruby-dev \
    qpdf poppler-utils \
    bulk-extractor \
    gdb gdb-multiarch radare2 \
    crackmapexec evil-winrm chisel impacket-scripts \
    metasploit-framework postgresql \
    tmux \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

RUN gem install zsteg 2>/dev/null || true

# ============================================================
# Phase 4: Python Security Packages
# ============================================================
RUN pip3 install --break-system-packages --force-reinstall "capstone==5.0.3" -i https://pypi.tuna.tsinghua.edu.cn/simple/ 2>/dev/null || true
RUN pip3 install --break-system-packages --ignore-installed chardet -i https://pypi.tuna.tsinghua.edu.cn/simple/ 2>/dev/null || true

RUN pip3 install --break-system-packages --ignore-installed \
    requests aiohttp jinja2 'httpx[cli]' ratelimit beautifulsoup4 websockets clairvoyance lxml \
    pycryptodomex pycryptodome gmpy2 sympy z3-solver factordb-pycli \
    pwntools ropper \
    volatility3 scapy pillow pyzbar numpy scipy \
    pyjwt base58 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ 2>/dev/null || true

# 编译工具链卸载释放空间
RUN apt-get purge -y --auto-remove \
    build-essential gcc g++ cmake python3-dev \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev ruby-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# ============================================================
# Phase 5: Git-based Tools
# ============================================================
# JWT Tool
RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool 2>/dev/null || true && \
    rm -rf /opt/tools/jwt_tool/.git 2>/dev/null || true

# tplmap - SSTI scanner
RUN git clone --depth=1 https://github.com/epinna/tplmap.git /opt/tools/tplmap 2>/dev/null || true && \
    rm -rf /opt/tools/tplmap/.git 2>/dev/null || true

# XSStrike - XSS scanner
RUN git clone --depth=1 https://github.com/s0md3v/XSStrike.git /opt/tools/XSStrike 2>/dev/null || true && \
    rm -rf /opt/tools/XSStrike/.git 2>/dev/null || true && \
    if [ -f /opt/tools/XSStrike/requirements.txt ]; then \
        pip3 install --break-system-packages -r /opt/tools/XSStrike/requirements.txt 2>/dev/null || true; \
    fi

# Gopherus - SSRF exploitation
RUN git clone --depth=1 https://github.com/tarunkant/Gopherus.git /opt/tools/Gopherus 2>/dev/null || true && \
    rm -rf /opt/tools/Gopherus/.git 2>/dev/null || true

# phpggc - PHP deserialization chains
RUN git clone --depth=1 https://github.com/ambionics/phpggc.git /opt/tools/phpggc 2>/dev/null || true && \
    rm -rf /opt/tools/phpggc/.git 2>/dev/null || true

# RsaCtfTool - RSA attacks
RUN git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/tools/RsaCtfTool 2>/dev/null || true && \
    rm -rf /opt/tools/RsaCtfTool/.git 2>/dev/null || true && \
    if [ -f /opt/tools/RsaCtfTool/requirements.txt ]; then \
        pip3 install --break-system-packages -r /opt/tools/RsaCtfTool/requirements.txt 2>/dev/null || true; \
    fi

# pwndbg - GDB plugin for PWN
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg.git /opt/tools/pwndbg 2>/dev/null || true && \
    if [ -d /opt/tools/pwndbg ]; then cd /opt/tools/pwndbg && ./setup.sh 2>/dev/null || true; fi

# nuclei-templates
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates 2>/dev/null || true \
    && rm -rf /root/.local/nuclei-templates/.git 2>/dev/null || true

# vulhub - CVE PoC 参考库
RUN git clone --depth=1 https://github.com/vulhub/vulhub.git /opt/tools/vulhub 2>/dev/null || true \
    && cd /opt/tools/vulhub \
    && find . -type f \( -name "docker-compose.*" -o -name "Dockerfile" -o -name "*.sh" \
        -o -name "*.sql" -o -name "*.conf" -o -name "*.xml" -o -name "*.yml" \
        -o -name "*.yaml" -o -name "*.jar" -o -name "*.war" -o -name "*.tar" \
        -o -name "*.gz" -o -name "*.zip" -o -name "*.key" -o -name "*.pem" \
        -o -name "*.crt" -o -name "*.properties" -o -name "*.ini" -o -name "*.cfg" \
        -o -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" \
        -o -name "*.svg" -o -name "*.ico" -o -name "*.pdf" -o -name "*.lock" \
        -o -name ".gitignore" -o -name ".dockerignore" -o -name "*.css" \
        -o -name "LICENSE*" -o -name "Makefile" \) -delete 2>/dev/null; \
    find . -type d -empty -delete 2>/dev/null; \
    rm -rf .git

# one_gadget
RUN gem install one_gadget 2>/dev/null || true

# ROPgadget
RUN pip3 install --break-system-packages ROPgadget 2>/dev/null || true

# Remove PEP 668 marker
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true

# ============================================================
# Phase 6: Binary Tools
# ============================================================
RUN mkdir -p /opt/tools/ysoserial && \
    wget -qO /opt/tools/ysoserial/ysoserial-all.jar \
    "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" 2>/dev/null || true

# jadx - Android/Java Decompiler
RUN JADX_VERSION="1.5.5" && \
    wget -qO /tmp/jadx.zip \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" 2>/dev/null && \
    mkdir -p /opt/tools/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/tools/jadx 2>/dev/null && \
    chmod +x /opt/tools/jadx/bin/jadx 2>/dev/null && \
    ln -sf /opt/tools/jadx/bin/jadx /usr/local/bin/jadx 2>/dev/null || true

# ============================================================
# Phase 7: ProjectDiscovery Tools (httpx, katana)
# ============================================================
RUN set -x; \
    arch=$(uname -m); \
    if [ "$arch" = "x86_64" ]; then platform="linux_amd64"; \
    elif [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then platform="linux_arm64"; \
    else platform="linux_amd64"; fi; \
    KATANA_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
      | grep -o '"browser_download_url": *"[^"]*"' | grep "${platform}.zip" | head -1 | cut -d'"' -f4) 2>/dev/null || true; \
    if [ -n "$KATANA_URL" ]; then \
      wget -qO /tmp/katana.zip "$KATANA_URL" 2>/dev/null && \
      unzip -q /tmp/katana.zip -d /tmp/katana_extracted 2>/dev/null && \
      find /tmp/katana_extracted -type f -name katana -exec mv {} /usr/local/bin/katana \; 2>/dev/null && \
      chmod +x /usr/local/bin/katana 2>/dev/null; \
      rm -rf /tmp/katana.zip /tmp/katana_extracted; \
    fi; \
    HTTPX_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
      | grep -o '"browser_download_url": *"[^"]*"' | grep "${platform}.zip" | head -1 | cut -d'"' -f4) 2>/dev/null || true; \
    if [ -n "$HTTPX_URL" ]; then \
      wget -qO /tmp/httpx.zip "$HTTPX_URL" 2>/dev/null && \
      unzip -q /tmp/httpx.zip -d /tmp/httpx_extracted 2>/dev/null && \
      find /tmp/httpx_extracted -type f -name httpx -exec mv {} /usr/local/bin/httpx \; 2>/dev/null && \
      chmod +x /usr/local/bin/httpx 2>/dev/null; \
      rm -rf /tmp/httpx.zip /tmp/httpx_extracted; \
    fi

# ============================================================
# Phase 8: Wrapper Scripts (Web tools)
# ============================================================
RUN echo '#!/bin/bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"' > /usr/local/bin/jwt-tool && chmod +x /usr/local/bin/jwt-tool 2>/dev/null || true
RUN echo '#!/bin/bash\npython3 /opt/tools/tplmap/tplmap.py "$@"' > /usr/local/bin/tplmap && chmod +x /usr/local/bin/tplmap 2>/dev/null || true
RUN echo '#!/bin/bash\njava -jar /opt/tools/ysoserial/ysoserial-all.jar "$@"' > /usr/local/bin/ysoserial && chmod +x /usr/local/bin/ysoserial 2>/dev/null || true

# ============================================================
# Final: Working Directory
# ============================================================
WORKDIR /root/agent-work
CMD ["/bin/bash"]