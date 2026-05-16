"""DockerExecutor — Kali Linux 容器内命令执行"""
from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Optional

from .base import BaseExecutor, ExecutionResult

_logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import DockerException, NotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None
    DockerException = Exception
    NotFound = Exception


# Docker 镜像配置
# 默认使用本地构建的自定义镜像（含 Kali + 全套 CTF 工具链）
# 通过 docker/Dockerfile 构建，或设置 SANDBOX_IMAGE=kalilinux/kali-rolling 使用官方镜像
_KALI_IMAGE = os.getenv("SANDBOX_IMAGE", "ctf-agent-sandbox")
_CONTAINER_NAME = os.getenv("SANDBOX_CONTAINER", "ctf-agent-sandbox")
_DOCKERFILE_PATH = os.getenv(
    "SANDBOX_DOCKERFILE",
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "docker")
    ),
)
_MOUNT_SOURCE = os.getenv(
    "SANDBOX_MOUNT_SOURCE",
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")
    ),
)
_MOUNT_TARGET = os.getenv("SANDBOX_MOUNT_TARGET", "/root/agent-work")


class DockerExecutor(BaseExecutor):
    """在 Kali Linux Docker 容器内执行命令的沙箱执行器

    提供隔离的执行环境，预装渗透测试工具链。
    宿主机项目目录自动挂载到容器内 /root/agent-work/。

    使用方式：
        executor = DockerExecutor()
        result = executor.execute("nmap -sV target.com")
    """

    def __init__(
        self,
        container_name: str = _CONTAINER_NAME,
        image: str = _KALI_IMAGE,
        mount_source: str = _MOUNT_SOURCE,
        mount_target: str = _MOUNT_TARGET,
    ):
        if not DOCKER_AVAILABLE:
            raise ImportError(
                "Docker SDK 未安装，请运行: pip install docker\n"
                "或者设置 SANDBOX_MODE=local 使用本地执行（无隔离）"
            )

        self._container_name = container_name
        self._image = image
        self._mount_source = os.path.abspath(mount_source)
        self._mount_target = mount_target.rstrip("/")
        self._pool = ThreadPoolExecutor(max_workers=4)
        self._client: Optional[docker.DockerClient] = None
        self._container: Optional[docker.models.containers.Container] = None

    @property
    def name(self) -> str:
        return f"docker:{self._container_name}"

    def is_available(self) -> bool:
        try:
            c = self._get_client()
            c.ping()
            return True
        except Exception:
            return False

    # ── 容器生命周期 ──

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    @staticmethod
    def _get_dockerfile_path() -> str:
        """获取 Dockerfile 所在目录的路径"""
        path = _DOCKERFILE_PATH
        if os.path.isdir(path):
            return path
        # fallback: 项目根目录下的 docker/
        fallback = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "docker")
        )
        if os.path.isdir(fallback):
            return fallback
        raise FileNotFoundError(f"Dockerfile 目录未找到: {path}")

    def ensure_running(self) -> str:
        """确保容器运行，不存在则创建并启动

        Returns:
            容器状态描述
        """
        client = self._get_client()

        # 检查是否已有同名容器
        try:
            container = client.containers.get(self._container_name)
            if container.status == "running":
                self._container = container
                return f"容器 {self._container_name} 已在运行"
            # 容器存在但未运行 → 启动
            container.start()
            self._container = container
            return f"容器 {self._container_name} 已重启"
        except NotFound:
            pass

        # 确保镜像存在
        try:
            client.images.get(self._image)
        except docker.errors.ImageNotFound:
            if self._image == "ctf-agent-sandbox" or "/" not in self._image:
                # 本地自定义镜像 → 从 Dockerfile build
                df_path = self._get_dockerfile_path()
                _logger.info("构建镜像 %s (from %s)...", self._image, df_path)
                img, logs = client.images.build(
                    path=df_path,
                    tag=self._image,
                    rm=True,
                    forcerm=True,
                )
                for log in logs:
                    if "stream" in log:
                        _logger.info("  BUILD: %s", log["stream"].strip())
            else:
                # 外部镜像 → pull
                _logger.info("拉取镜像 %s ...", self._image)
                client.images.pull(self._image)

        # 创建容器
        host_work = self._mount_source

        volumes = {
            host_work: {
                "bind": self._mount_target,
                "mode": "rw",
            }
        }

        container = client.containers.create(
            image=self._image,
            name=self._container_name,
            command="tail -f /dev/null",  # 保持运行
            volumes=volumes,
            working_dir=self._mount_target,
            tty=True,
            stdin_open=True,
            network_mode="host",
            cap_add=["SYS_PTRACE"],
            security_opt=["seccomp=unconfined"],
        )
        container.start()
        self._container = container
        return f"容器 {self._container_name} 已创建并启动"

    def stop(self):
        """停止并删除容器"""
        if self._container:
            try:
                self._container.stop(timeout=5)
                self._container.remove()
            except Exception:
                pass
            self._container = None

    # ── 命令执行 ──

    def execute(
        self,
        command: str,
        *,
        timeout: int = 120,
        workdir: Optional[str] = None,
        caller: str = "",
    ) -> ExecutionResult:
        """在容器内执行命令

        Args:
            command: Shell 命令
            timeout: 超时秒数
            workdir: 工作目录（容器内路径），默认挂载根目录
            caller: 调用方标识

        Returns:
            ExecutionResult
        """
        if self._container is None:
            self.ensure_running()

        container = self._container
        assert container is not None, "容器未初始化"

        # 若无 workdir，默认用挂载目录
        cmd_workdir = workdir or self._mount_target

        # 转换路径：如果 workdir 是宿主机路径，转为容器内路径
        if os.path.isabs(cmd_workdir) and cmd_workdir.startswith(self._mount_source):
            rel = os.path.relpath(cmd_workdir, self._mount_source)
            cmd_workdir = f"{self._mount_target}/{rel}".replace("\\", "/")

        return self._exec_internal(
            container, command, timeout=timeout,
            workdir=cmd_workdir, caller=caller,
        )

    def _exec_internal(
        self,
        container,
        command: str,
        *,
        timeout: int,
        workdir: str,
        caller: str,
    ) -> ExecutionResult:
        """在容器内执行命令（流式收集输出，支持超时部分输出）"""
        exec_cmd = ["/bin/bash", "-c", command]
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        exec_id_holder: list[str] = []

        def _run():
            api = container.client.api
            exec_id = api.exec_create(
                container.id,
                cmd=exec_cmd,
                workdir=workdir,
                stdout=True,
                stderr=True,
            )["Id"]
            exec_id_holder.append(exec_id)

            for out, err in api.exec_start(exec_id, stream=True, demux=True):
                if out:
                    stdout_parts.append(out.decode("utf-8", errors="replace"))
                if err:
                    stderr_parts.append(err.decode("utf-8", errors="replace"))

        future = self._pool.submit(_run)
        try:
            future.result(timeout=timeout)
        except TimeoutError:
            # 超时：收集部分输出
            if exec_id_holder:
                try:
                    insp = container.client.api.exec_inspect(exec_id_holder[0])
                    pid = insp.get("Pid", 0)
                    if pid and pid > 0:
                        container.exec_run(f"kill -9 {pid}", detach=True)
                except Exception:
                    pass

            partial_out = "".join(stdout_parts)
            partial_err = "".join(stderr_parts)
            note = f"\n[TIMEOUT] 命令执行超时 ({timeout}s)"
            _logger.warning("Docker exec timeout: %s | caller=%s", command[:80], caller)
            return ExecutionResult(
                exit_code=-1,
                stdout=partial_out,
                stderr=partial_err + note,
                command=command,
                timed_out=True,
                container_name=self._container_name,
            )

        # 正常完成
        exit_code = -1
        if exec_id_holder:
            try:
                insp = container.client.api.exec_inspect(exec_id_holder[0])
                exit_code = insp.get("ExitCode", -1) or 0
            except Exception:
                pass

        return ExecutionResult(
            exit_code=exit_code,
            stdout="".join(stdout_parts).strip(),
            stderr="".join(stderr_parts).strip(),
            command=command,
            container_name=self._container_name,
        )

    def __del__(self):
        self._pool.shutdown(wait=False)
