"""
HTTP 工具
==========

提供 HTTP 请求封装，用于信息收集阶段的快速探测。
失败时自动重试，超时控制。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

import requests

from ..common import log_system_event


def get_with_retry(
    url: str,
    *,
    timeout: int = 10,
    max_retries: int = 3,
    headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """发送 GET 请求，失败时自动重试

    Args:
        url: 目标 URL
        timeout: 超时秒数
        max_retries: 最大重试次数
        headers: 自定义请求头

    Returns:
        requests.Response 对象

    Raises:
        requests.RequestException: 所有重试均失败
    """
    for attempt in range(max_retries + 1):
        try:
            return requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers=headers or {},
            )
        except requests.exceptions.RequestException as e:
            if attempt >= max_retries:
                raise
            delay = attempt + 1
            log_system_event(
                f"请求失败，准备重试",
                f"url={url} attempt={attempt + 1}/{max_retries} delay={delay}s error={e}",
            )
            time.sleep(delay)


def probe_endpoint(
    url: str,
    method: str = "GET",
    timeout: int = 10,
) -> Dict[str, Any]:
    """快速探测单个端点

    返回端点状态、响应头、响应体长度等信息，不保存完整内容。

    Returns:
        {"url": str, "status_code": int, "headers": dict, "body_length": int, "error": str|None}
    """
    result = {"url": url, "status_code": 0, "headers": {}, "body_length": 0, "error": None}
    try:
        resp = get_with_retry(url, timeout=timeout)
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["body_length"] = len(resp.text)
    except requests.exceptions.Timeout:
        result["error"] = f"超时 ({timeout}s)"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"连接失败: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


__all__ = ["get_with_retry", "probe_endpoint"]