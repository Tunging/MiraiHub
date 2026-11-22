"""CodeArts 的本机路径表（平台知识，不放进共享模块）。

## 固定的是名字，动态的是位置

安装目录名 ``CodeArts``、数据目录名 ``codearts``、主程序 ``CodeArts.exe``
是客户端写死的，不会变；会变的是**装在哪个盘**和**用户新建的父文件夹**，
由 `admin.platform.install_paths` 动态定位（所有实际存在的盘 + 三层父目录）。

```
Windows
<任意盘>/<任意父目录>/CodeArts/
  CodeArts.exe
  resources/app.asar
  resources/build/icon.png
%APPDATA%/codearts/                        ← userData（登录态）
  Local State                            ← OSCrypt 主密钥（DPAPI 保护）
  secretStorage/<sha256>.enc             ← authSession:cn-north-4

macOS
/Applications/CodeArts Agent.app/Contents/{Info.plist,MacOS,Resources/app}
~/Library/Application Support/CodeArts Agent/   ← userData
  User/globalStorage/state.vscdb
```

## 为什么必须按平台分表

`%APPDATA%` 是 **Windows 写法**：`install_paths.expand()` 在非 Windows 上
展开不了它（没有这个环境变量），于是模板串被原样留在结果里 —— 界面上就
成了「配置目录：`%APPDATA%\\codearts`」，扫描永远判定「没装客户端」。
macOS 的 `appData` 是 `~/Library/Application Support`，而且 CodeArts 在
macOS 上发的是 VS Code 系的 `CodeArts Agent`（目录名带空格、大写）。

所以：**模板按平台生成，搜索根也按平台给**，一处都不写死盘符 / `%VAR%`。

覆盖（任选其一，立即生效）：环境变量 ``CODEARTS_INSTALL_DIR`` /
``CODEARTS_USER_DATA_DIR`` / ``CODEARTS_APP_EXE``，或后台「客户端路径」设置。
"""
from __future__ import annotations

import os
import pathlib
import plistlib
import sys

from admin.platform import install_paths as ip

PLATFORM = "codearts"

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"

#: 固定的目录名 / 文件名（**不要写盘符**）
INSTALL_NAMES = (("CodeArts Agent.app", "CodeArts.app") if IS_MAC
                 else ("CodeArts", "codearts"))
EXE_NAMES = () if IS_MAC else ("CodeArts.exe",)
DATA_NAMES = (("CodeArts Agent", "codearts", "CodeArts") if IS_MAC
              else ("codearts",))

#: 用于确认「这个同名目录确实是 CodeArts」（macOS 是 .app 包，判据在 Contents 下）
INSTALL_REQUIRE = ("Contents/Info.plist",) if IS_MAC else ("resources/app.asar",)

#: 数据目录判据：Windows 必须同时有 Local State + secretStorage（沿用原判据，
#: 避免把 Edge WebView、钉钉等 Electron 目录算进来）；macOS 的登录态在
#: `User/globalStorage/state.vscdb` 里，两种形态哪个先出现都算数。
DATA_REQUIRE = () if IS_MAC else ("Local State", "secretStorage")
DATA_MARKERS = ("User/globalStorage/state.vscdb", "secretStorage", "Local State") \
    if IS_MAC else ()

#: 数据目录的搜索根（**平台差异只在这一行**）
DATA_ROOTS = (("~/Library/Application Support",) if IS_MAC
              else (r"%APPDATA%",) if IS_WIN
              else ("~/.config",))

#: 安装包的搜索根（macOS 的 .app 常被拖到 /Applications 或 ~/Downloads 直接跑）
INSTALL_ROOTS = (("/Applications", "~/Applications", "~/Downloads") if IS_MAC
                 else ())

#: UA 前缀用的产品名
UA_PRODUCT = "CodeArts Agent" if IS_MAC else "CodeArts"

#: 兼容旧调用方：保留**不含盘符**的环境变量模板
APP_EXE_CANDIDATES = (
    (r"%LOCALAPPDATA%\Programs\CodeArts\CodeArts.exe",
     r"%PROGRAMFILES%\CodeArts\CodeArts.exe") if IS_WIN else ())
DATA_DIR_CANDIDATES = (
    (r"%APPDATA%\codearts",) if IS_WIN
    else ("~/Library/Application Support/CodeArts Agent",) if IS_MAC
    else ("~/.config/codearts",))


def default_data_dir() -> str:
    """找不到时给用户看的「预期目录」（已按平台展开，不再出现 `%VAR%`）。"""
    raw = DATA_DIR_CANDIDATES[0]
    return str(ip.expand(raw))


def bundle_executable(bundle: str) -> str:
    """macOS `.app` 里的主程序（Windows 的 exe 在这里叫 Contents/MacOS/<name>）。

    读 `Info.plist` 的 `CFBundleExecutable`；读不到就退到 `Contents/MacOS/`
    下唯一可执行的文件 —— 名字可能被客户端改过，不硬拼。
    """
    contents = os.path.join(str(bundle), "Contents")
    macos = os.path.join(contents, "MacOS")
    name = ""
    try:
        with open(os.path.join(contents, "Info.plist"), "rb") as fh:
            name = str(plistlib.load(fh).get("CFBundleExecutable") or "")
    except (OSError, ValueError, plistlib.InvalidFileException):
        name = ""
    if name:
        path = os.path.join(macos, name)
        if os.path.isfile(path):
            return path
    try:
        entries = sorted(os.listdir(macos))
    except OSError:
        return ""
    for entry in entries:
        path = os.path.join(macos, entry)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def install_dirs() -> list[str]:
    if IS_MAC:
        return ip.resolve(PLATFORM, kind="install_dir", names=INSTALL_NAMES,
                          require=INSTALL_REQUIRE, roots=INSTALL_ROOTS,
                          max_depth=1)
    # Windows：位置动态（任意盘 + 三层父目录），判据和行为保持原样
    return ip.resolve(PLATFORM, kind="install_dir", names=INSTALL_NAMES,
                      require=INSTALL_REQUIRE)


def app_exe_candidates() -> list[str]:
    """主程序绝对路径列表（找不到返回空列表，交给 probe 照常兜底）。"""
    if not IS_MAC:
        return ip.resolve(PLATFORM, kind="app_exe", names=INSTALL_NAMES,
                          exe_names=EXE_NAMES, require=INSTALL_REQUIRE,
                          fallback=APP_EXE_CANDIDATES)
    out: list[str] = []
    value, _ = ip.override(PLATFORM, "app_exe")
    if value and os.path.isfile(value):
        out.append(value)
    for bundle in install_dirs():
        exe = bundle_executable(bundle)
        if exe and exe not in out:
            out.append(exe)
    return out


def data_dir_candidates(*, all_matches: bool = False) -> list[str]:
    """userData 目录（存在的优先）。"""
    return ip.resolve(PLATFORM, kind="user_data_dir", names=DATA_NAMES,
                      require=DATA_REQUIRE, markers=DATA_MARKERS,
                      roots=DATA_ROOTS,
                      fallback=DATA_DIR_CANDIDATES, max_depth=0,
                      stop_after_first=not all_matches)


def data_dir() -> str:
    dirs = data_dir_candidates()
    return dirs[0] if dirs else default_data_dir()
