# CTF Agent Sandbox — Kali Linux 安全工具镜像
# Build: docker build -t ctf-agent-sandbox docker/
#
# 核心工具必须安装成功，非必需工具可跳过。

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# ============================================================
# Phase 1: 镜像源配置（必须成功）
# ============================================================
RUN set -eux; \
    mirrors="mirrors.aliyun.com/kali mirrors.cloud.tencent.com/kali mirrors.tencent.com/kali mirrors.tuna.tsinghua.edu.cn/kali ftp.acc.umu.se/mirror/kali.org/kali"; \
    for m in $mirrors; do \
        [ "$success" = 1 ] && break; \
        echo "deb http://$m kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        apt-get update 2>/dev/null && success=1 && echo "MIRROR OK: $m"; \
    done; \
    [ "$success" = 1 ] || ( echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && apt-get update )

# ============================================================
# Phase 2: 基础系统（必须成功）
# ============================================================
RUN apt-get install -y --no-install-recommends \
    python3 python3-pip python-is-python3 \
    curl wget git jq unzip tree file xxd ca-certificates openssl \
    iputils-ping dnsutils net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================
# Phase 3: 核心安全工具（必须成功）
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    netcat-traditional \
    tcpdump \
    hydra \
    ffuf \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================
# Phase 4: 扩展工具（可选，失败不影响核心功能）
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    whatweb nuclei socat \
    binwalk steghide imagemagick \
    tshark john gdb radare2 hexedit \
    ruby tmux ffmpeg sox \
    python3-requests python3-bs4 python3-lxml \
    2>/dev/null; \
    apt-get clean && rm -rf /var/lib/apt/lists/* 2>/dev/null; \
    true

# ============================================================
# Phase 5: Python 包（可选）
# ============================================================
RUN pip3 install --break-system-packages --ignore-installed \
    pwntools pycryptodomex gmpy2 sympy z3-solver \
    pillow pyzbar numpy \
    2>/dev/null || true

RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true

# ============================================================
# Phase 6: 本地漏洞库（可选）
# ============================================================
RUN git clone --depth=1 https://github.com/vulhub/vulhub.git /opt/tools/vulhub 2>/dev/null || true
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates 2>/dev/null || true

WORKDIR /root/agent-work
CMD ["/bin/bash"]