"""Load the trusted probe inventory from a local configuration file.

Only public keys and host allow-lists are read from configuration.  Revocation
state deliberately lives in SQLite instead, so editing or replacing the
configuration file can never un-revoke a probe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class ConfigError(Exception):
    """A fail-closed configuration error safe to show at startup."""


@dataclass(frozen=True)
class ProbeConfig:
    probe_id: str
    public_key_pem: str
    authorized_hosts: frozenset[str]
    key_fingerprint: str

    @property
    def public_key(self):
        # Parsing PEM on each import would be wasteful but still bounded.  The
        # key object cannot be frozen in a dataclass, so parse it lazily here.
        return serialization.load_pem_public_key(self.public_key_pem.encode("utf-8"))

    def as_public_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "authorized_hosts": sorted(self.authorized_hosts),
            "key_fingerprint": self.key_fingerprint,
        }


def _fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return "SHA256:" + ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _load_public_key(config_dir: Path, item: dict) -> rsa.RSAPublicKey:
    pem = item.get("public_key_pem")
    key_file = item.get("public_key_file") or item.get("public_key_path")

    if pem is not None and key_file is not None:
        raise ConfigError("探针配置不能同时指定 public_key_pem 与 public_key_file")
    if pem is not None:
        if not isinstance(pem, str) or not pem.strip():
            raise ConfigError("public_key_pem 必须是非空 PEM 字符串")
        pem_bytes = pem.encode("utf-8")
    elif key_file is not None:
        if not isinstance(key_file, str) or not key_file.strip():
            raise ConfigError("public_key_file 必须是非空路径")
        path = Path(key_file)
        if not path.is_absolute():
            path = config_dir / path
        try:
            pem_bytes = path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"无法读取探针公钥文件：{key_file}") from exc
    else:
        raise ConfigError("探针配置必须包含 public_key_pem 或 public_key_file")

    try:
        key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise ConfigError("探针公钥不是有效的 PEM 公钥") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ConfigError("探针公钥必须是 RSA 公钥")
    return key


def load_probe_config(path: str | Path) -> dict[str, ProbeConfig]:
    """Load and validate probe definitions.

    The shipped configuration contains two probes.  The loader accepts a
    positive number of probes so the service can also be exercised in isolated
    test deployments, while still rejecting duplicates and empty inventories.
    """

    config_path = Path(path)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"无法读取探针配置文件：{config_path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("探针配置文件不是有效的 UTF-8 JSON") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("probes"), list):
        raise ConfigError("探针配置文件必须包含 probes 数组")
    if not payload["probes"]:
        raise ConfigError("探针配置至少需要一台探针")

    probes: dict[str, ProbeConfig] = {}
    for index, item in enumerate(payload["probes"]):
        if not isinstance(item, dict):
            raise ConfigError(f"第 {index + 1} 个探针配置不是对象")
        probe_id = item.get("probe_id")
        if not isinstance(probe_id, str) or not probe_id.strip():
            raise ConfigError(f"第 {index + 1} 个探针缺少有效的 probe_id")
        probe_id = probe_id.strip()
        if probe_id in probes:
            raise ConfigError(f"探针 ID 重复：{probe_id}")

        hosts = item.get("authorized_hosts")
        if not isinstance(hosts, list) or not hosts:
            raise ConfigError(f"探针 {probe_id} 至少需要一个授权主机")
        normalized_hosts: set[str] = set()
        for host in hosts:
            if not isinstance(host, str) or not host.strip():
                raise ConfigError(f"探针 {probe_id} 包含无效的授权主机")
            normalized_hosts.add(host.strip())

        key = _load_public_key(config_path.parent, item)
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        probes[probe_id] = ProbeConfig(
            probe_id=probe_id,
            public_key_pem=pem,
            authorized_hosts=frozenset(normalized_hosts),
            key_fingerprint=_fingerprint(key),
        )
    return probes


def default_config_path() -> Path:
    return Path(
        os.environ.get(
            "PROBE_CONFIG",
            str(Path(__file__).resolve().parent.parent / "config" / "probes.json"),
        )
    )
