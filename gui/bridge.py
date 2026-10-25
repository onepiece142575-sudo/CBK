#!/usr/bin/env python3
"""cbk.exe 进程桥。只做三件事：起进程、传参、把 stdout JSON 回吐给 GUI。

约定（来自 cbk.exe 的头注释）：
  - stdout 每行一个完整 JSON，事件类型：start / progress / warn / result
  - stderr 只放人类可读的错误文本
  - 密码走 stdin，绝不走命令行参数
  - 退出码：0 成功 / 1 部分成功 / 2 失败 / 3 参数错误
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any


def _validate_password(password: str | None) -> None:
    if password is not None and any(ch in password for ch in ("\r", "\n", "\0")):
        raise ValueError("密码不能包含换行或空字符，请重新输入。")
    if password is not None:
        try:
            password.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("密码包含无法编码的字符，请重新输入。") from exc


# ------------------------------------------------------------------ exe 路径


def _find_cbk_exe() -> str:
    env = os.environ.get("CBK_EXE")
    if env:
        return str(Path(env).expanduser().resolve())
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cbk.exe")
    if os.path.isfile(local):
        return local
    root = Path(__file__).resolve().parent.parent
    for relative in ("code/build/msvc/bin/Release/cbk.exe", "code/build/msvc/bin/Debug/cbk.exe"):
        candidate = root / relative
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("cbk") or shutil.which("cbk.exe")
    if found:
        return found
    return str(root / "code/build/msvc/bin/Release/cbk.exe")


CBK_EXE = _find_cbk_exe()

EventCb = Callable[[dict[str, Any]], None]
TextCb = Callable[[str], None]
ExitCb = Callable[[int], None]


# ------------------------------------------------------------------ 句柄


class CbkProcess:
    """一次 cbk.exe 运行。GUI 拿这个发取消、查状态。"""

    def __init__(self, proc: subprocess.Popen):
        self._proc = proc

    def poll(self) -> int | None:
        return self._proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._proc.wait(timeout=timeout)

    def cancel(self) -> None:
        """优先 Ctrl+Break（让 cbk 自己清理半成品），失败则强杀。

        注意：因为用了 CREATE_NEW_PROCESS_GROUP，CTRL_BREAK_EVENT 只会
        发给 cbk 的进程组，不会影响我们自己的进程。如果当前进程没有
        控制台（比如 pythonw 打包运行），GenerateConsoleCtrlEvent 会失败，
        这时退化为 terminate()——会留下半成品，是可接受的降级。
        """
        if self._proc.poll() is not None:
            return
        try:
            self._proc.send_signal(signal.CTRL_BREAK_EVENT)
        except Exception:
            try:
                self._proc.terminate()
            except Exception:
                pass

        def ensure_exit():
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    self._proc.kill()
                    self._proc.wait()
                except OSError:
                    pass

        threading.Thread(target=ensure_exit, daemon=True).start()


# ------------------------------------------------------------------ 内核


def _start(
    args: list[str],
    password: str | None,
    on_event: EventCb,
    on_error: TextCb,
    on_exit: ExitCb | None,
) -> CbkProcess:
    """起一个流式 cbk 进程：一边跑一边吐事件。"""
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        # 如果不想弹黑框，可以再 | subprocess.CREATE_NO_WINDOW，
        # 但那样 CTRL_BREAK_EVENT 大概率失效，取消会退化成强杀。

    _validate_password(password)
    proc = subprocess.Popen(
        [CBK_EXE] + args,
        stdin=subprocess.PIPE if password is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=creationflags,
    )

    def read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("expected a JSON object")
            except ValueError as exc:
                on_error(f"[bridge] stdout 非 JSON: {exc}: {line}")
                continue
            on_event(obj)

    def read_stderr() -> None:
        # 逐行回调，不要攒到最后——否则用户看到的是"点了开始没反应"。
        assert proc.stderr is not None
        for line in proc.stderr:
            on_error(line.rstrip("\r\n"))

    def watch() -> None:
        t_out.join()
        t_err.join()
        code = proc.wait()
        proc.stdout.close()
        proc.stderr.close()
        if args and args[0] == "backup":
            # A forcefully stopped worker cannot run its C++ destructor. Remove
            # only that worker's uniquely owned partial archive, never the target.
            destination = args[args.index("--dest") + 1]
            partial = Path(destination + f".partial-{proc.pid}")
            try:
                partial.unlink(missing_ok=True)
            except OSError as exc:
                on_error(f"未能清理未完成的备份：{exc}")
        if on_exit:
            on_exit(code)

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_wat = threading.Thread(target=watch, daemon=True)
    t_out.start()
    t_err.start()

    if password is not None and proc.stdin is not None:
        try:
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    t_wat.start()
    return CbkProcess(proc)


def _run_capture(
    args: list[str],
    password: str | None,
    timeout: float = 60.0,
    cancel_event: threading.Event | None = None,
) -> str:
    """起一个一次性 cbk 进程，拿完整 stdout（list / verify 用）。"""
    _validate_password(password)
    proc = subprocess.Popen(
        [CBK_EXE] + args,
        stdin=subprocess.PIPE if password is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    deadline = time.monotonic() + timeout
    input_text = password + "\n" if password is not None else None
    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("任务已取消")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"cbk {args[0]} 超时（>{timeout}s）")
            try:
                out, err = proc.communicate(input=input_text, timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                input_text = None
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        proc.communicate()
        raise
    if proc.returncode != 0:
        raise RuntimeError(err.strip() or f"cbk {args[0]} 失败，退出码 {proc.returncode}")
    return out


# ------------------------------------------------------------------ 公开 API


def get_algorithms() -> dict[str, Any]:
    """同步取算法列表（cbk info）。GUI 启动时调一次。"""
    out = _run_capture(["info"], None, timeout=5.0)
    data = json.loads(out)
    if not isinstance(data, dict) or any(
        not isinstance(data.get(key), list)
        or any(not isinstance(item, str) or not item for item in data[key])
        for key in ("packers", "compressors", "ciphers")
    ):
        raise ValueError("后台程序返回的算法列表格式不正确。")
    return data


def run_backup(
    *,
    source: str,
    dest: str,
    packer: str,
    compress: str | None = None,
    encrypt: str | None = None,
    password: str | None = None,
    follow_symlinks: bool = False,
    on_event: EventCb,
    on_error: TextCb,
    on_exit: ExitCb | None = None,
) -> CbkProcess:
    if encrypt and not password:
        raise ValueError("加密备份必须填写非空密码。")
    args = ["backup", "--source", source, "--dest", dest, "--packer", packer, "--progress", "json"]
    if compress:
        args += ["--compress", compress]
    if encrypt:
        args += ["--encrypt", encrypt]
    if follow_symlinks:
        args += ["--follow-symlinks"]
    if password is not None:
        args += ["--password-stdin"]
    return _start(args, password, on_event, on_error, on_exit)


def run_restore(
    *,
    archive: str,
    dest: str,
    overwrite: str = "skip",
    no_metadata: bool = False,
    password: str | None = None,
    on_event: EventCb,
    on_error: TextCb,
    on_exit: ExitCb | None = None,
) -> CbkProcess:
    args = [
        "restore",
        "--archive",
        archive,
        "--dest",
        dest,
        "--overwrite",
        overwrite,
        "--progress",
        "json",
    ]
    if no_metadata:
        args += ["--no-metadata"]
    if password is not None:
        args += ["--password-stdin"]
    return _start(args, password, on_event, on_error, on_exit)


def list_archive(
    archive: str,
    password: str | None = None,
    as_json: bool = True,
    timeout: float = 30.0,
    cancel_event: threading.Event | None = None,
) -> Any:
    args = ["list", "--archive", archive]
    if as_json:
        args += ["--json"]
    if password is not None:
        args += ["--password-stdin"]
    out = _run_capture(args, password, timeout=timeout, cancel_event=cancel_event)
    return json.loads(out) if as_json else out


def verify_archive(
    archive: str, timeout: float = 1800.0, cancel_event: threading.Event | None = None
) -> None:
    _run_capture(["verify", "--archive", archive], None, timeout=timeout, cancel_event=cancel_event)
