"""
高级侦察工具
=============

提供 nmap 扫描（端口/服务/OS）+ whatweb 扫描（Web 指纹识别），
补充 HTTP header 级别的技术栈识别。

whatweb 通过 HTTP 请求解析指纹，不依赖 TCP 连接握手，
适合 tcpwrapped / CDN 场景。
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from ..common import log_system_event

_logger = logging.getLogger(__name__)

# ── 端口服务到技术栈的映射 ──

_PORT_HINTS: Dict[int, Tuple[str, str]] = {
    3306: ("MySQL", "database"),
    5432: ("PostgreSQL", "database"),
    1521: ("Oracle", "database"),
    27017: ("MongoDB", "database"),
    6379: ("Redis", "database"),
    11211: ("Memcached", "database"),
    80: ("HTTP", "server"),
    443: ("HTTPS", "server"),
    8080: ("HTTP-Proxy", "server"),
    8443: ("HTTPS-Alt", "server"),
    22: ("SSH", "remote"),
    21: ("FTP", "remote"),
}

_SERVICE_LANGUAGE_HINTS = {
    "php": "PHP",
    "tomcat": "Java",
    "jetty": "Java",
    "spring": "Java",
    "wsgi": "Python",
    "gunicorn": "Python",
    "uwsgi": "Python",
    "flask": "Python",
    "django": "Python",
    "fastapi": "Python",
    "node.js": "JavaScript",
    "express": "JavaScript",
    "next.js": "JavaScript",
    "nuxt": "JavaScript",
    "asp.net": "ASP.NET",
    "dotnet": "ASP.NET",
    "iis": "ASP.NET",
    "fiber": "Go",
}
# NOTE: 不使用单字母/短词 (go, gin, asp, node) 做子串匹配，
# 避免 "nginx"→gin→Go、"openssh"→asp→ASP.NET 等误报。

_SERVICE_DB_HINTS = {
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "oracle": "Oracle",
    "redis": "Redis",
    "memcached": "Memcached",
    "sqlite": "SQLite",
    "mssql": "Microsoft SQL Server",
    "sqlserver": "Microsoft SQL Server",
}


async def nmap_scan(
    target: str,
    *,
    timeout: int = 120,
    args: str = "-sV -sC -O --max-retries 2 --min-rate 500",
) -> Dict[str, Any]:
    """通过沙箱执行 nmap 扫描并解析结果

    通过 get_executor() 在 Docker 容器（或本地）内执行 nmap，
    不在宿主机直接调 nmap。

    Args:
        target: 目标 IP 或域名
        timeout: 整体超时秒数
        args: nmap 参数（默认 -sV -sC -O）

    Returns:
        ports / os / raw_xml / error
    """
    from ..sandbox import get_executor

    loop = asyncio.get_event_loop()

    # 检查 nmap 是否可用（通过沙箱）
    try:
        check = await loop.run_in_executor(
            None, lambda: get_executor().execute("nmap --version", timeout=10)
        )
        if check.exit_code != 0:
            return {"ports": [], "os": "", "os_cpe": "", "raw_xml": "", "error": "nmap not available in sandbox"}
    except Exception as e:
        log_system_event(f"nmap 检查失败: {e}", level=logging.WARNING)
        return {"ports": [], "os": "", "os_cpe": "", "raw_xml": "", "error": f"nmap check failed: {e}"}

    log_system_event(f"开始 nmap 扫描: {target} ({args})")

    cmd = f"nmap {args} -oX - {target} 2>/dev/null"
    try:
        result = await loop.run_in_executor(
            None,
            lambda: get_executor().execute(cmd, timeout=timeout, caller="nmap_scan"),
        )
    except Exception as e:
        log_system_event(f"nmap 扫描异常: {e}", level=logging.WARNING)
        return {"ports": [], "os": "", "os_cpe": "", "raw_xml": "", "error": str(e)}

    raw_xml = result.stdout
    if result.timed_out:
        log_system_event("nmap 扫描超时", level=logging.WARNING)
        return {"ports": [], "os": "", "os_cpe": "", "raw_xml": "", "error": f"timeout ({timeout}s)"}

    if not raw_xml.strip():
        log_system_event("nmap 无输出", level=logging.WARNING)
        return {"ports": [], "os": "", "os_cpe": "", "raw_xml": "", "error": "empty output"}

    return _parse_nmap_xml(raw_xml)


def _parse_nmap_xml(raw_xml: str) -> Dict[str, Any]:
    """解析 nmap XML 输出"""
    result: Dict[str, Any] = {
        "ports": [],
        "os": "",
        "os_cpe": "",
        "raw_xml": raw_xml,
        "error": None,
    }

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        result["error"] = f"XML parse error: {e}"
        return result

    # ── 操作系统识别 ──
    os_elem = root.find(".//os")
    if os_elem is not None:
        # 取第一个 osmatch 的名称
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            result["os"] = osmatch.get("name", "")
            # 取第一个 osclass 的 cpe
            osclass = osmatch.find("osclass")
            if osclass is not None:
                cpe = osclass.find("cpe")
                if cpe is not None and cpe.text:
                    result["os_cpe"] = cpe.text.strip()

    # ── 端口与服务识别 ──
    for port_elem in root.findall(".//port"):
        port_num = port_elem.get("portid")
        protocol = port_elem.get("protocol", "tcp")
        state_elem = port_elem.find("state")
        service_elem = port_elem.find("service")

        if not port_num or state_elem is None:
            continue

        state = state_elem.get("state", "unknown")
        if state != "open":
            continue

        entry = {
            "port": int(port_num),
            "protocol": protocol,
            "state": state,
            "service": service_elem.get("name", "") if service_elem is not None else "",
            "product": service_elem.get("product", "") if service_elem is not None else "",
            "version": service_elem.get("version", "") if service_elem is not None else "",
            "extrainfo": service_elem.get("extrainfo", "") if service_elem is not None else "",
        }

        # 拼接完整版本字符串
        version_parts = []
        if entry["product"]:
            version_parts.append(entry["product"])
        if entry["version"]:
            version_parts.append(entry["version"])
        if entry["extrainfo"]:
            version_parts.append(f"({entry['extrainfo']})")
        entry["version_str"] = " ".join(version_parts)

        result["ports"].append(entry)

    log_system_event(
        "nmap 扫描完成",
        f"开放端口={len(result['ports'])} OS={result['os'] or 'unknown'}",
    )
    return result


# ── whatweb Web 指纹识别 ──


async def whatweb_scan(
    target: str,
    *,
    timeout: int = 60,
    aggressive: bool = True,
) -> Dict[str, Any]:
    """通过沙箱执行 whatweb 扫描，识别 Web 技术栈

    whatweb 通过 HTTP 请求解析指纹（headers / cookies / body），
    不依赖 TCP 连接握手，适合 tcpwrapped / CDN 场景。

    Args:
        target: 目标 URL（如 http://host:port/path）
        timeout: 超时秒数
        aggressive: 是否启用 --aggressive 模式（更多请求，更准）

    Returns:
        plugins / raw_output / error
    """
    from ..sandbox import get_executor

    loop = asyncio.get_event_loop()

    # 检查 whatweb 是否可用
    try:
        check = await loop.run_in_executor(
            None, lambda: get_executor().execute("whatweb --version", timeout=10)
        )
        if check.exit_code != 0:
            return {"plugins": [], "raw_output": "", "error": "whatweb not available in sandbox"}
    except Exception as e:
        log_system_event(f"whatweb 检查失败: {e}", level=logging.WARNING)
        return {"plugins": [], "raw_output": "", "error": f"whatweb check failed: {e}"}

    args = "--aggressive" if aggressive else ""
    cmd = f"whatweb {args} '{target}' 2>/dev/null".strip()

    log_system_event(f"开始 whatweb 扫描: {target}" + (" (aggressive)" if aggressive else ""))

    try:
        result = await loop.run_in_executor(
            None,
            lambda: get_executor().execute(cmd, timeout=timeout, caller="whatweb_scan"),
        )
    except Exception as e:
        log_system_event(f"whatweb 扫描异常: {e}", level=logging.WARNING)
        return {"plugins": [], "raw_output": "", "error": str(e)}

    raw = result.stdout.strip()
    if not raw:
        return {"plugins": [], "raw_output": "", "error": "empty output"}

    plugins = _parse_whatweb_output(raw)

    log_system_event(
        "whatweb 扫描完成",
        f"识别 {len(plugins)} 个组件",
    )
    return {"plugins": plugins, "raw_output": raw, "error": None}


def _parse_whatweb_output(raw: str) -> List[Dict[str, str]]:
    """解析 whatweb 文本输出

    格式: http://url [Status] Plugin1[val1][val2], Plugin2[val], ...

    Returns:
        [{name, version, all_values}, ...]
    """
    # 提取插件部分（在状态码之后）
    match = re.search(r'\]\s+(.+)', raw)
    if not match:
        return []

    plugins_text = match.group(1)
    plugins: List[Dict[str, str]] = []

    # 按逗号分割每个插件
    for part in plugins_text.split(", "):
        part = part.strip()
        if not part:
            continue

        # 解析 PluginName[value1][value2]...
        name_match = re.match(r'^([^\[]+?)((?:\[[^\]]*\])*)$', part)
        if not name_match:
            plugins.append({"name": part, "version": "", "all_values": []})
            continue

        name = name_match.group(1).strip()
        brackets = name_match.group(2)

        # 提取所有 [] 内的值
        values = re.findall(r'\[([^\]]*)\]', brackets)
        version = values[0] if values else ""

        plugins.append({"name": name, "version": version, "all_values": values})

    return plugins


def enrich_from_whatweb(
    tech_stack: Any,
    whatweb_result: Dict[str, Any],
) -> None:
    """用 whatweb 扫描结果丰富 TechStack

    whatweb 比 nmap -sV 更适合 tcpwrapped 场景，
    因为它通过 HTTP 请求解析指纹，不依赖 TCP 连接握手。
    """
    if whatweb_result.get("error") or not whatweb_result.get("plugins"):
        return

    plugins = whatweb_result["plugins"]
    plugin_names = {p["name"].lower() for p in plugins}
    name_to_plugin: dict = {}
    for p in plugins:
        name_to_plugin[p["name"].lower()] = p

    _SERVER_NAMES = frozenset({
        "openresty", "nginx", "apache", "apache httpd", "httpd", "iis",
        "tomcat", "caddy", "lighttpd",
    })
    _LANG_NAMES = frozenset({
        "php", "python", "java", "perl", "ruby", "asp.net",
    })
    _FRAMEWORK_NAMES = frozenset({
        "django", "flask", "fastapi", "express",
        "spring", "struts", "thinkphp", "laravel", "yii",
        "wordpress", "drupal", "joomla",
    })

    # Server
    for name in _SERVER_NAMES & plugin_names:
        p = name_to_plugin[name]
        tag = f"{p['name']} {p['version']}".strip()
        if not tech_stack.server:
            tech_stack.server = tag
            log_system_event(f"[WhatWeb] 识别 Server: {tech_stack.server}")
        if tag not in tech_stack.middleware:
            tech_stack.middleware.append(tag)

    # Language
    for name in _LANG_NAMES & plugin_names:
        p = name_to_plugin[name]
        if not tech_stack.language:
            tech_stack.language = p["name"]
            log_system_event(f"[WhatWeb] 识别语言: {tech_stack.language}")

    # Framework / CMS
    for name in _FRAMEWORK_NAMES & plugin_names:
        p = name_to_plugin[name]
        tag = f"{p['name']} {p['version']}".strip()
        if not tech_stack.framework:
            tech_stack.framework = tag
            log_system_event(f"[WhatWeb] 识别框架: {tech_stack.framework}")

    log_system_event(f"[WhatWeb] 组件列表: {[p['name'] for p in plugins]}")


def enrich_tech_stack(
    tech_stack: Any,
    nmap_result: Dict[str, Any],
) -> None:
    """用 nmap 扫描结果丰富 TechStack

    解析端口服务信息，推断：
    - 操作系统 (os)
    - 编程语言 (language)
    - 框架 (framework)
    - 数据库 (database)
    - 中间件 (middleware)
    """
    # ── OS ──
    if nmap_result.get("os") and not tech_stack.os:
        os_str = nmap_result["os"]
        tech_stack.os = os_str
        log_system_event(f"[Recon] 识别 OS: {os_str}")

    # ── 从端口服务推断技术栈 ──
    detected_languages = set()
    detected_databases = set()
    detected_middleware = set()

    _MIDDLEWARE_NAMES = frozenset({
        "nginx", "apache", "apache httpd", "httpd", "iis",
        "tomcat", "caddy", "traefik", "openresty",
        "envoy", "haproxy", "varnish", "squid",
    })

    for port_info in nmap_result.get("ports", []):
        service_name = port_info.get("service", "").lower()
        product = port_info.get("product", "").lower()
        version_str = port_info.get("version_str", "").lower()
        combined = f"{service_name} {product} {version_str}"

        # 检测数据库
        for hint, db_name in _SERVICE_DB_HINTS.items():
            if hint in combined:
                detected_databases.add(db_name)

        # 检测语言/框架（仅匹配完整 product 字段，避免子串误报）
        for hint, lang in _SERVICE_LANGUAGE_HINTS.items():
            if hint in product or hint in service_name:
                detected_languages.add(lang)

        # 检测中间件（检查 service 和 product 两个字段）
        check_mw = service_name if service_name not in ("http", "https", "tcpwrapped") else product
        if check_mw and check_mw in _MIDDLEWARE_NAMES:
            label = product or service_name
            entry = f"{label} {port_info['version_str']}".strip()
            if entry not in detected_middleware:
                detected_middleware.add(entry)

    if detected_languages and not tech_stack.language:
        # 取最具体的一个（比如 Java 比 OpenResty 的 Nginx 更有意义）
        priority = ["PHP", "Java", "ASP.NET", "Python", "Go", "JavaScript"]
        for lang in priority:
            if lang in detected_languages:
                tech_stack.language = lang
                break
        else:
            tech_stack.language = next(iter(detected_languages))
        log_system_event(f"[Recon] 识别语言: {tech_stack.language}")

    if detected_databases and not tech_stack.database:
        tech_stack.database = next(iter(detected_databases))
        log_system_event(f"[Recon] 识别数据库: {tech_stack.database}")

    if detected_middleware:
        existing = set(tech_stack.middleware)
        for m in detected_middleware:
            if m not in existing:
                tech_stack.middleware.append(m)
        log_system_event(f"[Recon] 中间件: {tech_stack.middleware}")

    # 额外：HTTP 端口上的 Server header 常被中间层（openresty/nginx）覆盖
    # 如果有端口 8080/8443 等非标准 web 端口开着不同服务，那才是 real backend


__all__ = ["nmap_scan", "whatweb_scan", "enrich_from_whatweb", "enrich_tech_stack"]