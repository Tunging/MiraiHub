"""macOS 上 Electron / VS Code 的 safeStorage（Chromium OSCrypt）解密。

## 为什么不能复用 Windows 那套

两端都叫 `safeStorage`、密文都以 `v10` 开头，但**语义完全不同**：

```
Windows:  v10 | nonce(12) | AES-256-GCM 密文
          密钥来自 Local State 的 os_crypt.encrypted_key（DPAPI 保护）

macOS:    v10 | AES-128-CBC 密文（PKCS#7，IV = 16 个空格）
          密钥 = PBKDF2(Keychain 里的口令, salt="saltysalt", iter=1003, dkLen=16)
```

把任一套套到另一套上，得到的都只是一句 `InvalidTag` 或 padding 非法 ——
所以这里按平台分文件，调用方（各平台的 `core/session.py`）按 `sys.platform`
选路，不共用分支。

## Keychain 里那条口令

Chromium 系的 service 名是 `<产品名> Safe Storage`（account 同名），
产品名取自 `Info.plist` 的 `CFBundleName` / Electron 的 `productName`。
各平台产品名不同（`CodeArts Agent` / `CodeArts`），所以 service 名由调用方给，
这里只负责「按候选顺序找第一条能读到的」。

读取用系统自带的 `security` 命令，不引入 pyobjc：

    security find-generic-password -s "<产品名> Safe Storage" -w

⚠️ 第一次访问某条目时，macOS 可能弹「xxx 想使用钥匙串中的机密信息」。
弹窗期间命令会**阻塞**，所以这里一律带超时 —— 否则一次扫描能把
后台请求线程卡死（比报错更难查）。
"""
from __future__ import annotations

import hashlib
import subprocess
import sys

#: Chromium 派生口令用的固定盐与迭代次数（写死在 OSCrypt 里，不是配置）
SALT = b"saltysalt"
ITERATIONS = 1003
#: macOS 的 IV 是 16 个空格（Chromium 的老习惯，别改成随机值）
IV = b" " * 16

#: Keychain 里 service 名的后缀
KEYCHAIN_SUFFIX = " Safe Storage"


class MacStorageError(Exception):
    """keychain 读不到 / 解不出。`kind` 供上层区分展示文案。"""

    def __init__(self, message: str, *, kind: str = "keychain",
                 detail: str = ""):
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.detail = detail


def service_name(product: str) -> str:
    """`CodeArts Agent` -> `CodeArts Agent Safe Storage`（已带后缀时原样返回）。"""
    text = str(product or "").strip()
    if not text:
        return ""
    return text if text.endswith(KEYCHAIN_SUFFIX) else text + KEYCHAIN_SUFFIX


#: 读 Keychain 的默认超时（秒）。
#:
#: 不能给 2~3 秒：条目若还没被授权，macOS 会弹「`security` 想使用钥匙串中的
#: 机密信息」，用户在弹窗上点下去之前命令是**阻塞**的。给太短只会一直“超时”，
#: 用户明明点了也没用（还会以为是网关坏了）。给太长又会拖住请求线程，
#: 因此取 15 秒：足够点一下，不行就如实报错。
DEFAULT_TIMEOUT = 15.0


def find_keychain_password(service: str, *, timeout: float = DEFAULT_TIMEOUT
                            ) -> tuple[str, str]:
    """读一条 Keychain 通用密码。返回 `(口令, 错误说明)`；读不到时口令为空串。

    不走 shell、不写任何东西；`security` 自带 `-w` 只输出口令本身。
    """
    name = str(service or "").strip()
    if not name:
        return "", "未指定 Keychain service 名"
    if sys.platform != "darwin":
        return "", "只有 macOS 才有 Keychain"
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-s", name, "-w"],
            capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "", "找不到 security 命令（不是标准 macOS 环境？）"
    except subprocess.TimeoutExpired:
        return "", ("读取 Keychain 超时（可能弹出了授权窗口没人点）：%s" % name)
    except OSError as exc:  # noqa: BLE001 - 权限/沙箱等
        return "", str(exc)
    if proc.returncode != 0:
        # 44 = errSecItemNotFound：多半是客户端换了产品名，或从未在这台机器登录
        return "", (proc.stderr or "").strip() or ("Keychain 中没有 %s" % name)
    password = (proc.stdout or "").strip()
    if not password:
        return "", "Keychain 中的口令为空：%s" % name
    return password, ""


def first_keychain_password(services, *, timeout: float = DEFAULT_TIMEOUT
                            ) -> tuple[str, str, str]:
    """按顺序试多个 service 名，返回 `(口令, 命中的 service, 错误说明)`。"""
    errors: list[str] = []
    for service in services or ():
        password, error = find_keychain_password(service, timeout=timeout)
        if password:
            return password, service, ""
        if error:
            errors.append(error)
    return "", "", "；".join(errors[-3:])


def derive_key(password: str, *, iterations: int = ITERATIONS,
               length: int = 16) -> bytes:
    """Keychain 口令 -> OSCrypt 的 AES 密钥（macOS 用 16 字节 / AES-128）。"""
    text = str(password or "")
    if not text:
        raise MacStorageError("Keychain 口令为空", kind="keychain")
    return hashlib.pbkdf2_hmac("sha1", text.encode("utf-8"), SALT,
                               iterations, length)


def decrypt_v10(raw: bytes, key: bytes) -> bytes:
    """解 macOS 的 `v10` 密文（AES-128-CBC + PKCS#7）。

    只做 CBC：macOS 的 OSCrypt 至今没有换过格式（换的是 Windows 侧）。
    若将来真换成 GCM，这里的 padding 校验会失败并如实报错 ——
    不静默返回半截明文。
    """
    body = bytes(raw or b"")
    if not body.startswith(b"v10"):
        raise MacStorageError(
            "不是 macOS 的 v10 密文（前缀=%r）" % body[:3], kind="decrypt")
    payload = body[3:]
    if not payload or len(payload) % 16:
        raise MacStorageError(
            "密文长度不是 16 的整数倍（%d），不像 AES-CBC" % len(payload),
            kind="decrypt")
    secret = bytes(key or b"")
    if len(secret) < 16:
        raise MacStorageError("密钥长度不足 16 字节（%d）" % len(secret),
                              kind="decrypt")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - 环境缺库
        raise MacStorageError("缺少 cryptography 依赖，无法解密登录态",
                              kind="unsupported", detail=str(exc)) from exc
    decryptor = Cipher(algorithms.AES(secret[:16]), modes.CBC(IV)).decryptor()
    plain = decryptor.update(payload) + decryptor.finalize()
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        raise MacStorageError(
            "解密失败（padding 非法）：Keychain 口令与密文不匹配，"
            "通常是换了 macOS 账户 / 把数据目录拷到了别的机器", kind="decrypt")
    return plain[:-pad]


__all__ = ["MacStorageError", "service_name", "find_keychain_password",
           "first_keychain_password", "derive_key", "decrypt_v10",
           "SALT", "ITERATIONS", "IV", "DEFAULT_TIMEOUT"]
