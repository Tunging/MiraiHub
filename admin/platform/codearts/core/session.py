"""CodeArts 本机登录态读取与令牌续期。

## 凭证到底存在哪（实测路径，**两代客户端不一样**）

Windows（CodeArts Doer，Electron）：

```
%APPDATA%/codearts/Local State                     ← os_crypt.encrypted_key（DPAPI）
%APPDATA%/codearts/secretStorage/<sha256(key)>.enc ← authSession:cn-north-4
```

macOS（CodeArts Agent，VS Code 系）：

```
~/Library/Application Support/CodeArts Agent/User/globalStorage/state.vscdb
  ItemTable[ secret://{"extensionId":"huaweicloud.authentication",
                       "key":"HuaweiCloudSession"} ]
    = {"type":"Buffer","data":[118,49,48,...]}   ← 同一个 v10 密文，换了外壳
```

`secretStorage` 是客户端自己的 `FileSecretStorageService`：
文件名是 **key 的 sha256**，内容是 **base64(Chromium OSCrypt 密文)**。
Electron 在 Windows 上走的是 Chromium 的 `v10` 格式，不是裸 DPAPI：

```
v10 | nonce(12) | AES-256-GCM 密文（含 16 字节 tag）
        ↑ AES key 来自 Local State 里被 DPAPI 保护的 os_crypt.encrypted_key
```

所以 Windows 是两步：DPAPI 解出 AES key（`DPAPI` 前缀要去掉 5 字节），
再用 AES-GCM 解 `.enc`（`v10` 前缀要去掉 3 字节，剩下 12 字节 nonce）。

macOS **没有 DPAPI**：`v10` 是 `AES-128-CBC`，密钥由 Keychain 里的
`<产品名> Safe Storage` 口令经 PBKDF2 派生（见 `admin.platform.mac_safe_storage`）。
两端都叫 `v10` 但语义不同，**不能共用一条解密分支**。

## 存的是什么（两代结构，字段名也不同）

Windows：

```json
{"session": {"accessKey","secretKey","securityToken","refreshToken",
             "expiresAt","userId","userName","domainId","clientId", ...},
 "loginContext": {"pkcePair": {"codeVerifier": "..."},
                  "dpopKeyPair": {"privateKey": "{JWK}", "publicKey": "{JWK}"}}}}
```

macOS：

```json
{"account": {"id","label"}, "accessKey", "secretKey", "securitytoken",
 "expires_at": "2026-11-22T08:08:24.83Z", "domainId", "refresh_token",
 "loginContext": {"pkcePair": {"codeVerifier"},
                  "dpopKeyPair": {"privateKeyJwk": {...}, "publicKeyJwk": {...}}}}
```

所以读取时统一过一个 `_session_from_payload()` 归一化：AK/SK/STS 的正名
（`securitytoken` / `security_token` / `securityToken`）、到期时间的三种写法
（毫秒数 / ISO / 嵌套 `credentials`）、DPoP 密钥的两种形态（JSON 串 / JWK 对象）。

`loginContext` 里那两样是**续期的钥匙**：华为云 STS 的刷新要求
`code_verifier` + `DPoP` 头（ES256 JWT，公钥内嵌在头里）。
它们都随登录态一起落盘，所以本网关可以**独立续期**，不必依赖客户端在跑。

## 四个必须自觉的点

1. 只读，不写客户端文件 —— 注入/篡改是另一个能力（workbuddy 才有），
   CodeArts 这里绝不回写，避免把用户客户端搞坏。
2. 客户端每小时会刷新并重写这份文件；我们每次用之前重新读一遍，
   拿到的永远是「当下有效」的那份。
3. 路径不存在 / 存储形态不认识时，返回结构化错误而不是抛裸异常 ——
   `scan()` 要能区分「客户端没装」和「装了但没登录」。
4. macOS 要读 Keychain，可能弹授权框。一律带超时，且读不到就报
   `kind="keychain"`（附候选 service 名），不要卡住请求线程。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import pathlib
import sys
import time
from dataclasses import dataclass, field

logger = logging.getLogger("admin.platform.codearts.session")

#: 客户端产品名（`app.getPath("userData")` 的目录名，实测全小写）
APP_DIR_NAME = "codearts"

#: 会话在 secretStorage 里的逻辑 key（区域后缀来自 product.json 的 auth.region）
SESSION_KEY = "authSession:cn-north-4"

#: macOS 的 CodeArts Agent（VS Code 系）把登录态存在
#: `User/globalStorage/state.vscdb` 的 ItemTable 里，键是
#: `secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}`。
#: 用「像」匹配而不是整串等值：键里的 extensionId 顺序 / 空白可能随版本变。
VSCODE_SECRET_MARK = "HuaweiCloudSession"
VSCODE_SECRET_QUERY = "secret://%" + VSCODE_SECRET_MARK + "%"

#: STS 令牌端点（product.json 的 `auth.iamStsHost` + `/v1/oauth2/tokens`）
STS_TOKEN_URL = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"
#: Windows 客户端的 OAuth client id（product.json 的 `auth.clientId`）
CLIENT_ID = "codearts"
#: macOS 客户端的 client id（product.json 的 `urlProtocol`，刷新时上游按它认人）
AGENT_CLIENT_ID = "codearts-agent"


class SessionError(Exception):
    """读不到 / 解不开本机登录态。`kind` 供上层区分展示文案。"""

    def __init__(self, message: str, *, kind: str = "unavailable",
                 detail: str = ""):
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.detail = detail


# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
def data_dirs() -> list[str]:
    """本机存在的 userData 目录（覆盖值优先，其次按平台自动发现）。"""
    from admin.platform.codearts.core import paths

    return paths.data_dir_candidates(all_matches=True)


def _has_credentials(directory: str) -> bool:
    """目录里到底有没有登录态**文件**（先判存在，再谈能不能解）。"""
    return (os.path.isfile(state_db_file(directory))
            or os.path.isfile(secret_file(SESSION_KEY, directory)))


def app_data_dir() -> str:
    """客户端 userData 目录（动态定位，可由 ``CODEARTS_USER_DATA_DIR`` 覆盖）。

    不再拼死 `%APPDATA%/codearts`：用户可能改了 userData 目录名、用便携版
    `--user-data-dir`，或系统根本不在 C 盘（macOS 在
    `~/Library/Application Support`）。解析规则见 `core/paths.py`。

    多个候选时**优先有登录态那份**：同一台机器上 Windows 版和 VS Code 系
    可能共存，拿错目录会变成「客户端没登录」的假结论。
    """
    from admin.platform.codearts.core import paths

    dirs = data_dirs()
    for directory in dirs:
        if _has_credentials(directory):
            return directory
    return dirs[0] if dirs else paths.default_data_dir()


def state_db_file(directory: str | None = None) -> str:
    """VS Code 系的登录态数据库（macOS 的 `CodeArts Agent` 用这个）。"""
    return os.path.join(directory or app_data_dir(),
                        "User", "globalStorage", "state.vscdb")


def secret_dir(directory: str | None = None) -> str:
    return os.path.join(directory or app_data_dir(), "secretStorage")


def secret_file(key: str = SESSION_KEY, directory: str | None = None) -> str:
    return os.path.join(secret_dir(directory),
                        hashlib.sha256(key.encode("utf-8")).hexdigest() + ".enc")


def local_state_file(directory: str | None = None) -> str:
    return os.path.join(directory or app_data_dir(), "Local State")


def installed() -> bool:
    return bool(data_dirs())


def credential_source() -> str:
    """实际在读的那份登录态文件（扫描结果展示用，不泄任何秘密）。"""
    dirs = data_dirs() or [app_data_dir()]
    for directory in dirs:
        db = state_db_file(directory)
        if os.path.isfile(db):
            return db
        enc = secret_file(SESSION_KEY, directory)
        if os.path.isfile(enc):
            return enc
    return secret_file()


# ---------------------------------------------------------------------------
# 解密
# ---------------------------------------------------------------------------
def _dpapi_unprotect(data: bytes) -> bytes:
    """Windows DPAPI 解密（CryptUnprotectData）。"""
    if sys.platform != "win32":
        raise SessionError("当前系统不支持 DPAPI 解密", kind="unsupported")
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise SessionError("DPAPI 解密失败（换用户/换机器都会这样）",
                           kind="dpapi", detail=str(ctypes.GetLastError()))
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _aes_key(directory: str | None = None) -> bytes:
    """从 `Local State` 取 Chromium 的 OSCrypt 主密钥（32 字节）。"""
    path = local_state_file(directory)
    if not os.path.isfile(path):
        raise SessionError("找不到客户端的 Local State（客户端未登录或未装）",
                           kind="no_client", detail=path)
    try:
        state = json.loads(open(path, encoding="utf-8").read() or "{}")
    except (OSError, ValueError) as exc:
        raise SessionError("Local State 读取失败", kind="no_client",
                           detail=str(exc)) from exc
    encrypted = str((state.get("os_crypt") or {}).get("encrypted_key") or "")
    if not encrypted:
        raise SessionError("Local State 里没有 encrypted_key",
                           kind="no_client", detail=path)
    blob = base64.b64decode(encrypted)
    # Chromium 会在密文前加 5 字节 "DPAPI" 标记
    if blob[:5] == b"DPAPI":
        blob = blob[5:]
    key = _dpapi_unprotect(blob)
    if len(key) != 32:
        raise SessionError("OSCrypt 主密钥长度异常（%d）" % len(key),
                           kind="dpapi")
    return key


def _decode_key(raw: str) -> bytes:
    """把用户给的主密钥（hex 或 base64）解成字节。"""
    text = str(raw or "").strip()
    try:
        if len(text) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in text):
            return bytes.fromhex(text)
        return base64.b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise SessionError("主密钥不是合法的 hex / base64", kind="keychain",
                           detail=str(exc)) from exc


def _keychain_services() -> list[str]:
    """要试的 Keychain service 名（产品名随客户端版本变，列全了才能命中）。"""
    from admin.platform import mac_safe_storage as mss

    names = [(os.getenv("CODEARTS_KEYCHAIN_SERVICE") or "").strip(),
             "CodeArts Agent", "CodeArts", "codearts"]
    out: list[str] = []
    for name in names:
        service = mss.service_name(name)
        if service and service not in out:
            out.append(service)
    return out


def _mac_key() -> bytes:
    """macOS：Keychain 口令 → PBKDF2 派生 16 字节密钥（AES-128-CBC）。

    两个逃生门（容器 / 无图形会话 / Keychain 授权点不了时用）：
    ``CODEARTS_SAFE_STORAGE_PASSWORD``（直接给口令）或
    ``CODEARTS_SAFE_STORAGE_KEY``（直接给密钥，hex / base64）。
    """
    from admin.platform import mac_safe_storage as mss

    raw_key = (os.getenv("CODEARTS_SAFE_STORAGE_KEY") or "").strip()
    if raw_key:
        key = _decode_key(raw_key)
        if len(key) < 16:
            raise SessionError("CODEARTS_SAFE_STORAGE_KEY 不足 16 字节",
                               kind="keychain")
        return key
    password = (os.getenv("CODEARTS_SAFE_STORAGE_PASSWORD") or "").strip()
    if password:
        return mss.derive_key(password)
    services = _keychain_services()
    found, service, error = mss.first_keychain_password(services)
    if not found:
        raise SessionError("读不到 macOS Keychain 里的 safeStorage 口令",
                           kind="keychain",
                           detail=error or ("候选：" + " / ".join(services)))
    logger.debug("codearts: 已从 Keychain 读取口令（%s）", service)
    return mss.derive_key(found)


def _platform_key(directory: str | None = None) -> bytes:
    """Oscrypt 主密钥：Windows = DPAPI，macOS = Keychain。"""
    if sys.platform == "darwin":
        return _mac_key()
    return _aes_key(directory)


def decrypt_blob(raw: bytes, key: bytes) -> bytes:
    """解 Chromium OSCrypt 密文（两端都叫 `v10`，但格式不同）。

    * Windows：`v10` + nonce(12) + AES-256-GCM；
    * macOS：`v10` + AES-128-CBC（IV 是 16 个空格 + PKCS#7）。
    按平台分叉，**不要**用同一个分支试两种 —— 错的那种只会回一句
    `InvalidTag` / padding 非法，看不出到底哪里错了。
    """
    if sys.platform == "darwin":
        from admin.platform import mac_safe_storage as mss

        try:
            return mss.decrypt_v10(raw, key)
        except mss.MacStorageError as exc:
            raise SessionError("登录态解密失败（%s）" % exc.message,
                               kind=exc.kind, detail=exc.detail) from exc
    if raw[:3] == b"v10":
        nonce, ciphertext = raw[3:15], raw[15:]
    else:
        # 老格式（DPAPI 直存）：极少见，但保留兜底
        return _dpapi_unprotect(raw)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - 环境缺库
        raise SessionError("缺少 cryptography 依赖，无法解密登录态",
                           kind="unsupported", detail=str(exc)) from exc
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:  # noqa: BLE001 - 密钥不匹配/密文损坏
        raise SessionError("登录态解密失败（密钥与密文不匹配）",
                           kind="dpapi", detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# 读取
# ---------------------------------------------------------------------------
@dataclass
class LocalSession:
    """本机登录态（已归一成网关内部字段名）。"""

    access_key: str = ""
    secret_key: str = ""
    security_token: str = ""
    refresh_token: str = ""
    expires_at: int = 0            # 毫秒时间戳
    uid: str = ""
    user_name: str = ""
    domain_id: str = ""
    client_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    region: str = "cn-north-4"
    #: 续期用：DPoP 私钥与 PKCE code_verifier（JWK 原始 JSON 字符串）
    dpop_private_key: str = ""
    dpop_public_key: str = ""
    pkce_code_verifier: str = ""
    raw: dict = field(default_factory=dict)

    def to_credential(self) -> dict:
        """转成落库的 `auth_json` 结构（**不含**客户端私有字段）。"""
        return {
            "realm": "cn",
            "region": self.region,
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "security_token": self.security_token,
            "refresh_token": self.refresh_token,
            "expires_at": int(self.expires_at or 0),
            "uid": self.uid,
            "user_name": self.user_name,
            "domain_id": self.domain_id,
            "client_id": self.client_id or CLIENT_ID,
            # 续期材料：没有它们账号过期就只能重新登录
            "dpop_private_key": self.dpop_private_key,
            "dpop_public_key": self.dpop_public_key,
            "pkce_code_verifier": self.pkce_code_verifier,
            "source": "local",
        }

    @property
    def expires_in(self) -> int:
        """距离过期还有多少秒（负数=已过期）。"""
        if not self.expires_at:
            return 0
        return int(self.expires_at / 1000 - time.time())


def load_session(key: str = SESSION_KEY) -> LocalSession:
    """读并解密本机登录态（按存储形态逐个试）。失败一律抛 `SessionError`。

    两种形态都要认，因为同一个平台在 Windows / macOS 上根本不是同一份实现：

    * Electron：`<userData>/secretStorage/<sha256(key)>.enc`（Windows 客户端）；
    * VS Code：`<userData>/User/globalStorage/state.vscdb` 的 ItemTable（macOS 的
      `CodeArts Agent`）。

    先试有的那份，失败就换下一种 —— 「没登录」和「解不开」必须能分开报，
    否则用户看到的永远是「请先登录」，而客户端明明登录着。
    """
    dirs = data_dirs()
    if not dirs:
        raise SessionError("本机没有 CodeArts 客户端数据目录", kind="no_client",
                           detail=app_data_dir())

    errors: list[SessionError] = []
    for directory in dirs:
        db = state_db_file(directory)
        if os.path.isfile(db):
            try:
                return _load_vscode_state(db)
            except SessionError as exc:
                logger.debug("codearts: state.vscdb 读取失败 kind=%s: %s",
                             exc.kind, exc.detail)
                errors.append(exc)
        enc = secret_file(key, directory)
        if os.path.isfile(enc):
            try:
                return _load_secret_file(enc, directory)
            except SessionError as exc:
                logger.debug("codearts: secretStorage 读取失败 kind=%s: %s",
                             exc.kind, exc.detail)
                errors.append(exc)

    if errors:
        raise _pick_error(errors)
    raise SessionError("客户端没有已保存的登录态（可能未登录）", kind="no_login",
                       detail="; ".join(dirs))


#: 报错优先级：能说明「为什么解不开」的排前面，`no_login` 最不具体
_KIND_ORDER = ("keychain", "dpapi", "unsupported", "no_login", "unavailable")


def _pick_error(errors: list[SessionError]) -> SessionError:
    def rank(exc: SessionError) -> int:
        try:
            return _KIND_ORDER.index(exc.kind)
        except ValueError:
            return len(_KIND_ORDER)

    return sorted(errors, key=rank)[0]


def _decode_payload(raw: bytes, directory: str | None = None) -> dict:
    """密文 -> 登录态 JSON（解不开时抛带 kind 的 `SessionError`）。"""
    plain = decrypt_blob(raw, _platform_key(directory))
    try:
        payload = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SessionError("登录态不是合法 JSON", kind="no_login",
                           detail=str(exc)) from exc
    if not isinstance(payload, dict):
        raise SessionError("登录态不是 JSON 对象", kind="no_login")
    return payload


def _load_secret_file(path: str, directory: str | None = None) -> LocalSession:
    """Electron 的 `secretStorage/<sha256>.enc`（Windows 形态）。"""
    try:
        raw = base64.b64decode(open(path, "rb").read())
    except (OSError, ValueError) as exc:
        raise SessionError("登录态文件读取失败", kind="no_login",
                           detail=str(exc)) from exc
    return _session_from_payload(_decode_payload(raw, directory))


def _load_vscode_state(path: str) -> LocalSession:
    """VS Code 系的 `User/globalStorage/state.vscdb`（macOS 形态）。

    密文还是同一个 OSCrypt 的 `v10`，只是外壳从「一个 .enc 文件」换成了
    「SQLite 里的一行 `secret://…`」—— 所以解密分支与 Windows 共用，
    只是**平台不同**（macOS 走 CBC，见 `decrypt_blob`）。
    """
    raw = _read_vscode_secret(path)
    if not raw:
        raise SessionError("客户端没有已保存的登录态（可能未登录）",
                           kind="no_login", detail=path)
    return _session_from_payload(_decode_payload(raw))


def _sqlite_uris(path: str) -> list[str]:
    """只读打开用的 URI：先常规只读（能读到 WAL），再 immutable 兜底。

    客户端在跑时数据库是被锁着的，`mode=ro` 通常仍可读；万一连 WAL 都拿不到，
    `immutable=1` 至少能读出上次落盘的那份，不至于整条路走不通。
    """
    try:
        base = pathlib.Path(path).as_uri()
    except ValueError:
        base = "file:" + path
    return [base + "?mode=ro", base + "?immutable=1"]


def _read_vscode_secret(path: str) -> bytes:
    """从 state.vscdb 取出登录态密文；没有这一行时返回 `b""`。"""
    import sqlite3

    row = None
    error = ""
    for uri in _sqlite_uris(path):
        try:
            con = sqlite3.connect(uri, uri=True, timeout=3.0)
            try:
                row = con.execute(
                    "select value from ItemTable where key like ? limit 1",
                    (VSCODE_SECRET_QUERY,)).fetchone()
            finally:
                con.close()
            break
        except sqlite3.Error as exc:  # 被锁 / 不是 SQLite / 表不存在
            error = str(exc)
            continue
    if row is None:
        if error:
            raise SessionError("客户端登录态数据库读取失败", kind="no_login",
                               detail=error)
        return b""
    return _secret_buffer_bytes(row[0])


def _secret_buffer_bytes(value) -> bytes:
    """VS Code 把 Buffer 序列化成 `{"type":"Buffer","data":[...]}`。"""
    try:
        obj = json.loads(value)
    except (TypeError, ValueError):
        return b""
    if not isinstance(obj, dict):
        return b""
    data = obj.get("data")
    if isinstance(data, list):
        try:
            return bytes(int(byte) & 0xFF for byte in data)
        except (TypeError, ValueError):
            return b""
    if isinstance(data, str):
        try:
            return base64.b64decode(data)
        except (TypeError, ValueError):
            return b""
    return b""


def _text(*values) -> str:
    """取第一个非空值的字符串形式（两端字段名不同，按优先级试）。"""
    for value in values:
        if value is None or isinstance(value, (dict, list)):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _jwk_text(*values) -> str:
    """DPoP 密钥：Windows 存 JSON 串，macOS 存 JWK 对象 —— 统一成 JSON 串。"""
    for value in values:
        if isinstance(value, dict):
            return json.dumps(value, separators=(",", ":"))
        text = _text(value)
        if text:
            return text
    return ""


def _expires_ms(*values) -> int:
    """到期时间：毫秒数 / 数字串 / ISO 串，统一成毫秒时间戳。"""
    for value in values:
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
        text = str(value).strip()
        if text.isdigit():
            return int(text)
        parsed = _iso_to_ms(text)
        if parsed:
            return parsed
    return 0


def _default_client_id() -> str:
    """刷新用的 client_id：macOS 客户端是 `codearts-agent`，Windows 是 `codearts`。"""
    return AGENT_CLIENT_ID if sys.platform == "darwin" else CLIENT_ID


def _session_from_payload(payload: dict) -> LocalSession:
    """把客户端落盘的 JSON 归一成 `LocalSession`（兼容 Windows / macOS 两代）。

    两代的差异都在字段名上（`securityToken` vs `securitytoken`、
    `expiresAt`(毫秒) vs `expires_at`(ISO)、`privateKey`(JSON 串) vs
    `privateKeyJwk`(对象)），语义完全一样 —— 所以集中在这里抹平，
    解密与续期逻辑不需要知道数据是从哪个平台读出来的。
    """
    if not isinstance(payload, dict):
        raise SessionError("登录态不是 JSON 对象", kind="no_login")
    session = (payload.get("session")
               if isinstance(payload.get("session"), dict) else payload)
    creds = (session.get("credentials")
             if isinstance(session.get("credentials"), dict) else session)
    account = (session.get("account")
               if isinstance(session.get("account"), dict) else {})
    context = payload.get("loginContext") or session.get("loginContext") or {}

    access_key = _text(creds.get("accessKey"), creds.get("access_key_id"),
                       creds.get("access_key"))
    secret_key = _text(creds.get("secretKey"), creds.get("secret_access_key"),
                       creds.get("secret_key"))
    if not (access_key and secret_key):
        raise SessionError("登录态缺少 AK/SK（客户端需要重新登录）",
                           kind="no_login", detail="keys=%s" % list(creds))

    pkce = context.get("pkcePair") or {}
    dpop = context.get("dpopKeyPair") or {}
    return LocalSession(
        access_key=access_key,
        secret_key=secret_key,
        security_token=_text(creds.get("securityToken"), creds.get("securitytoken"),
                             creds.get("security_token")),
        refresh_token=_text(session.get("refreshToken"),
                            session.get("refresh_token")),
        expires_at=_expires_ms(creds.get("expiresAt"), creds.get("expires_at"),
                               creds.get("expiration")),
        uid=_text(creds.get("userId"), account.get("id")),
        user_name=_text(creds.get("userName"), account.get("label")),
        domain_id=_text(session.get("domainId"), session.get("domain_id")),
        client_id=_text(creds.get("clientId"), session.get("clientId"))
        or _default_client_id(),
        created_at=_text(session.get("createdAt"), session.get("created_at")),
        updated_at=_text(session.get("updatedAt"), session.get("updated_at")),
        dpop_private_key=_jwk_text(dpop.get("privateKey"),
                                   dpop.get("privateKeyJwk")),
        dpop_public_key=_jwk_text(dpop.get("publicKey"),
                                  dpop.get("publicKeyJwk")),
        pkce_code_verifier=_text(pkce.get("codeVerifier")),
        raw=session,
    )


# ---------------------------------------------------------------------------
# 续期（DPoP + PKCE）
# ---------------------------------------------------------------------------
def _b64u(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _ec_private_key(jwk_text: str):
    """从 JWK（P-256）还原私钥对象。"""
    from cryptography.hazmat.primitives.asymmetric import ec

    jwk = json.loads(jwk_text)
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SessionError("DPoP 私钥不是 P-256 EC", kind="refresh")
    raw = lambda name: int.from_bytes(  # noqa: E731 - 三行内更清楚
        base64.urlsafe_b64decode(jwk[name] + "=="), "big")
    public = ec.EllipticCurvePublicNumbers(raw("x"), raw("y"), ec.SECP256R1())
    return ec.EllipticCurvePrivateNumbers(raw("d"), public).private_key()


def dpop_proof(private_jwk: str, public_jwk: str, method: str, url: str, *,
               now: float | None = None) -> str:
    """生成 DPoP 头（ES256 JWT，公钥内嵌在 protected header）。

    ⚠️ JWS 的 ES256 签名是 **r||s 各 32 字节裸拼**，不是 DER ——
    直接把 `cryptography` 的返回值塞进去会得到「签名格式非法」。
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    public = json.loads(public_jwk)
    header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {key: public[key] for key in ("kty", "crv", "x", "y")},
    }
    payload = {
        "htm": method.upper(),
        "htu": url,
        "iat": int(now if now is not None else time.time()),
        "jti": os.urandom(8).hex(),
    }
    signing_input = b".".join([
        _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ])
    der = _ec_private_key(private_jwk).sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return (signing_input + b"." + _b64u(signature)).decode("ascii")


def refresh_session(credential: dict) -> dict:
    """用 refresh_token 换一组新的 STS 临时凭证。

    返回**新的凭证字典**（与入参同结构，已替换 AK/SK/STS/refresh_token）。
    失败抛 `SessionError(kind="refresh_dead")` —— 这种只能重新登录。

    注意：刷新不需要签名，但**必须**带 DPoP + code_verifier。
    """
    refresh_token = str(credential.get("refresh_token") or "")
    verifier = str(credential.get("pkce_code_verifier") or "")
    private = str(credential.get("dpop_private_key") or "")
    public = str(credential.get("dpop_public_key") or "")
    if not (refresh_token and verifier and private and public):
        raise SessionError(
            "缺少续期材料（refresh_token / code_verifier / DPoP 密钥）",
            kind="refresh_dead")

    payload = _refresh_with_client_id(credential, refresh_token, verifier,
                                      private, public)

    # ⚠️ 字段名是 `access_key_id` / `secret_access_key` / `expiration`(ISO)，
    # 不是 `access_key` / `secret_key` / `expires_in` —— 照客户端
    # `handleCallback()` 的映射抄，猜错就是「续期成功但 AK 为空」。
    credentials = payload.get("credentials") or {}
    access_key = str(credentials.get("access_key_id")
                     or credentials.get("access_key") or "")
    secret_key = str(credentials.get("secret_access_key")
                     or credentials.get("secret_key") or "")
    security_token = str(credentials.get("security_token") or "")
    if not (access_key and secret_key):
        raise SessionError("续期响应缺少 AK/SK", kind="refresh_dead",
                           detail=json.dumps(payload, ensure_ascii=False)[:300])

    expires_at = _iso_to_ms(str(credentials.get("expiration") or ""))
    if not expires_at:
        # 兜底：有些环境只回 expires_in（秒）
        expires_in = int(payload.get("expires_in") or 0)
        expires_at = int((time.time() + expires_in) * 1000) if expires_in else 0
    updated = dict(credential)
    updated.update({
        "access_key": access_key,
        "secret_key": secret_key,
        "security_token": security_token,
        # 注意：上游可能返回新的 refresh_token（轮转），不回写就会在下次失效
        "refresh_token": str(payload.get("refresh_token") or refresh_token),
        "expires_at": expires_at,
    })
    return updated


def _client_ids(credential: dict) -> list[str]:
    """刷新时按顺序试的 client_id。

    Windows 客户端是 `codearts`，macOS 的 CodeArts Agent 是 `codearts-agent`
    （= product.json 的 `urlProtocol`）。上游只回一句 `invalid_client`，
    不告诉我们对的是哪个 —— 所以凭证里存了就用它，再补两端的标准值兜底。
    """
    out: list[str] = []
    for value in (str(credential.get("client_id") or ""), _default_client_id(),
                  CLIENT_ID, AGENT_CLIENT_ID):
        if value and value not in out:
            out.append(value)
    return out


def _refresh_with_client_id(credential: dict, refresh_token: str, verifier: str,
                            private: str, public: str) -> dict:
    """按候选 client_id 依次尝试刷新。只有「不认这个 client_id」才换下一个。

    ⚠️ `refresh_token` 是一次性的：换 client_id **不消耗**它（上游在校验
    client 那一步就拒了），但把「被拒」当通用错误去重试整轮就会白打上游 ——
    所以这里只在错误文本明确指向 client 时才继续。
    """
    last: SessionError | None = None
    for client_id in _client_ids(credential):
        try:
            return _post_token(client_id, verifier, refresh_token, private, public)
        except SessionError as exc:
            last = exc
            if exc.kind != "refresh_dead" or "client" not in (exc.detail or "").lower():
                raise
            logger.info("codearts: 上游不认 client_id=%s，换下一个重试", client_id)
    raise last or SessionError("续期失败", kind="refresh_dead")


def _post_token(client_id: str, verifier: str, refresh_token: str,
                private: str, public: str) -> dict:
    """发一次 STS 换票请求，返回上游 JSON。"""
    import urllib.error
    import urllib.parse
    import urllib.request

    body = urllib.parse.urlencode({
        "client_id": client_id,
        "code_verifier": verifier,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "DPoP": dpop_proof(private, public, "POST", STS_TOKEN_URL),
    }
    request = urllib.request.Request(STS_TOKEN_URL, data=body, headers=headers,
                                     method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=40) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        raise SessionError("续期被上游拒绝（HTTP %d）" % exc.code,
                           kind="refresh_dead", detail=detail) from exc
    except Exception as exc:  # noqa: BLE001 - 网络
        raise SessionError("续期请求失败", kind="network",
                           detail=str(exc)[:200]) from exc


def _iso_to_ms(value: str) -> int:
    """`2026-11-04T07:04:36.628Z` -> 毫秒时间戳（解析失败返回 0）。"""
    text = (value or "").strip()
    if not text:
        return 0
    try:
        from datetime import datetime

        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0
