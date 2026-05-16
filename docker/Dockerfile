# CTF Agent Sandbox — Kali Linux 安全工具镜像
# Build: docker build -t ctf-agent-sandbox docker/

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# Phase 1: 配置 apt 源 + 基础系统
# 首次用 http://（基础镜像无 ca-certificates，HTTPS 证书校验会失败）
RUN rm -f /etc/apt/sources.list.d/*.sources \
    && echo "deb http://mirrors.aliyun.com/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip python-is-python3 \
        curl wget git jq unzip tree file xxd ca-certificates openssl \
        iputils-ping dnsutils net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 现在 ca-certificates 已装好，切回 https://
RUN echo "deb https://mirrors.aliyun.com/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

# Phase 2: 安全工具
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap sqlmap netcat-traditional tcpdump \
        whatweb nuclei \
        socat proxychains4 sslscan \
        hydra ffuf \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Phase 3: CTF 工具（取证/PWN/逆向）
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binwalk foremost steghide pngcheck imagemagick \
        ffmpeg sox tshark \
        john hexedit \
        gdb radare2 \
        ruby tmux \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Phase 4: Python 包（可选）
RUN pip3 install --break-system-packages --ignore-installed \
    requests aiohttp httpx beautifulsoup4 lxml \
    pwntools pycryptodomex gmpy2 sympy z3-solver \
    pillow pyzbar numpy \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ 2>/dev/null || true
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true

# Phase 5: 本地漏洞库（可选）
RUN git clone --depth=1 https://github.com/vulhub/vulhub.git /opt/tools/vulhub 2>/dev/null || true
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates 2>/dev/null || true

WORKDIR /root/agent-work
CMD ["/bin/bash"]
