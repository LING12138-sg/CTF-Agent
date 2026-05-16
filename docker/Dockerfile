# CTF Agent Sandbox — Kali Linux 安全工具镜像
# Build: docker build -t ctf-agent-sandbox docker/
# 国内源 + 逐阶段安装，单个包失败不影响整体

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive

# Phase 1: 镜像源配置
RUN apt-get update 2>/dev/null || true; \
    mirrors="mirrors.aliyun.com/kali mirrors.cloud.tencent.com/kali mirrors.tencent.com/kali"; \
    for m in $mirrors; do \
        echo "deb http://$m kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        if apt-get update 2>/dev/null; then echo "OK: $m"; break; fi; \
    done || true

# Phase 2: 基础系统
RUN apt-get install -y --no-install-recommends \
    python3 python3-pip python-is-python3 \
    curl wget git jq unzip tree file xxd ca-certificates openssl \
    iputils-ping dnsutils net-tools \
    2>/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/* || true

# Phase 3: 安全工具
RUN apt-get update 2>/dev/null; \
    apt-get install -y --no-install-recommends \
    nmap sqlmap netcat-traditional tcpdump \
    whatweb nuclei \
    socat hydra ffuf \
    2>/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/* || true

# Phase 4: CTF 工具
RUN apt-get update 2>/dev/null; \
    apt-get install -y --no-install-recommends \
    binwalk steghide imagemagick ffmpeg sox \
    tshark john gdb radare2 hexedit \
    ruby tmux \
    2>/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/* || true

# Phase 5: Python 包
RUN pip3 install --break-system-packages --ignore-installed \
    requests beautifulsoup4 lxml pwntools \
    pycryptodomex gmpy2 sympy z3-solver \
    pillow pyzbar numpy \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ 2>/dev/null || true

RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true

# Phase 6: vulhub + nuclei-templates（本地漏洞库）
RUN git clone --depth=1 https://github.com/vulhub/vulhub.git /opt/tools/vulhub 2>/dev/null || true
RUN git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates 2>/dev/null || true

WORKDIR /root/agent-work
CMD ["/bin/bash"]