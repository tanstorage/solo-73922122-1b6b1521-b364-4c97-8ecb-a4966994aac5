#!/usr/bin/env python3
"""Regenerate the demo public-key config and signed JSONL fixtures.

This development helper creates fresh RSA keys, writes only the public halves
into the configuration, signs the valid fixtures with the ephemeral private
keys, and then discards the private keys with the temporary directory.  The
running service never needs a private key.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def build_payloads() -> dict[str, list[dict]]:
    return {
        "probe-alpha": [
            {"probe_id": "probe-alpha", "event_id": "evt-0001", "host": "web-01.example.internal", "time": 1793000000, "rule": "webshell_upload_attempt"},
            {"probe_id": "probe-alpha", "event_id": "evt-0002", "host": "db-01.example.internal", "time": 1793000015, "rule": "suspicious_sql_login"},
            {"probe_id": "probe-alpha", "event_id": "evt-0003", "host": "web-01.example.internal", "time": 1793000031, "rule": "reverse_shell_egress"},
            {"probe_id": "probe-alpha", "event_id": "evt-0004", "host": "db-01.example.internal", "time": 1793000047, "rule": "privilege_escalation"},
            {"probe_id": "probe-alpha", "event_id": "evt-0005", "host": "web-01.example.internal", "time": 1793000060, "rule": "credential_dumping"},
            {"probe_id": "probe-alpha", "event_id": "evt-0005", "host": "web-01.example.internal", "time": 1793000060, "rule": "credential_dumping"},
        ],
        "probe-beta": [
            {"probe_id": "probe-beta", "event_id": "evt-1001", "host": "web-02.example.internal", "time": 1793000100, "rule": "malicious_dns_query"},
            {"probe_id": "probe-beta", "event_id": "evt-1002", "host": "db-02.example.internal", "time": 1793000120, "rule": "unauthorized_outbound"},
            {"probe_id": "probe-beta", "event_id": "evt-1003", "host": "web-02.example.internal", "time": 1793000144, "rule": "file_integrity_change"},
        ],
    }


AUTHORIZED_HOSTS = {
    "probe-alpha": ["web-01.example.internal", "db-01.example.internal"],
    "probe-beta": ["web-02.example.internal", "db-02.example.internal"],
}


def write_jsonl(path: Path, rows: list[dict]) -> bytes:
    payload = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    ).encode("utf-8")
    path.write_bytes(payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", default="config")
    parser.add_argument("--examples-dir", default="examples")
    args = parser.parse_args()

    config_dir = Path(args.config_dir)
    examples_dir = Path(args.examples_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    examples_dir.mkdir(parents=True, exist_ok=True)

    payloads = build_payloads()
    probe_entries = []
    with tempfile.TemporaryDirectory() as temporary:
        key_dir = Path(temporary)
        for probe_id in ("probe-alpha", "probe-beta"):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_pem = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_file = f"{probe_id}-public.pem"
            (config_dir / key_file).write_bytes(public_pem)
            private_path = key_dir / f"{probe_id}-private.pem"
            private_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            probe_entries.append(
                {
                    "probe_id": probe_id,
                    "public_key_file": key_file,
                    "authorized_hosts": AUTHORIZED_HOSTS[probe_id],
                }
            )

            data = write_jsonl(examples_dir / f"{probe_id}-valid.jsonl", payloads[probe_id])
            signature = key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32,
                ),
                hashes.SHA256(),
            )
            (examples_dir / f"{probe_id}-valid.sig").write_bytes(signature)

        # Tamper after signing: this fixture must be submitted with the valid
        # probe-alpha signature to demonstrate signature rejection.
        tampered = payloads["probe-alpha"]
        tampered[0] = {
            **tampered[0],
            "rule": "webshell_upload_attempt_tampered",
        }
        write_jsonl(examples_dir / "probe-alpha-tampered.jsonl", tampered)

    (config_dir / "probes.json").write_text(
        json.dumps({"probes": probe_entries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {config_dir / 'probes.json'} and signed fixtures under {examples_dir}")


if __name__ == "__main__":
    main()
