from __future__ import annotations

import base64
from contextlib import contextmanager
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.config import load_probe_config
from app.db import count_alerts, initialize_storage, list_probes, revoke_probe
from app.ingest import IngestError, ingest_batch
from app.main import create_app


def make_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return key, pem


def sign(key: rsa.RSAPrivateKey, data: bytes, *, salt_length: int = 32) -> bytes:
    return key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
        hashes.SHA256(),
    )


def make_jsonl(rows: list[dict]) -> bytes:
    return "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    ).encode("utf-8")


def event(
    probe_id: str = "probe-alpha",
    event_id: str = "evt-1",
    host: str = "web-01.example.internal",
    time_value: int = 1793000000,
    rule: str = "rule-a",
    **extra,
) -> dict:
    row = {
        "probe_id": probe_id,
        "event_id": event_id,
        "host": host,
        "time": time_value,
        "rule": rule,
    }
    row.update(extra)
    return row


class Keys:
    alpha_key: rsa.RSAPrivateKey
    beta_key: rsa.RSAPrivateKey
    alpha_pem: str
    beta_pem: str


def setUpModule() -> None:
    Keys.alpha_key, Keys.alpha_pem = make_keypair()
    Keys.beta_key, Keys.beta_pem = make_keypair()


def write_config(directory: Path) -> Path:
    """Write a two-probe local config using public key files."""

    (directory / "probe-alpha-public.pem").write_text(Keys.alpha_pem, encoding="utf-8")
    (directory / "probe-beta-public.pem").write_text(Keys.beta_pem, encoding="utf-8")
    config = {
        "probes": [
            {
                "probe_id": "probe-alpha",
                "public_key_file": "probe-alpha-public.pem",
                "authorized_hosts": ["web-01.example.internal", "db-01.example.internal"],
            },
            {
                "probe_id": "probe-beta",
                "public_key_file": "probe-beta-public.pem",
                "authorized_hosts": ["web-02.example.internal", "db-02.example.internal"],
            },
        ]
    }
    path = directory / "probes.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


@contextmanager
def app_client(config_path: Path, db_path: Path, staging_path: Path):
    app = create_app(
        config_path=config_path,
        db_path=db_path,
        staging_dir=staging_path,
    )
    with TestClient(app) as client:
        yield client


def upload(
    client: TestClient,
    *,
    probe_id: str,
    payload: bytes,
    signature: bytes,
    filename: str = "events.jsonl",
):
    return client.post(
        "/api/ingest",
        data={"probe_id": probe_id},
        files={
            "events": (filename, payload, "application/x-ndjson"),
            "signature": ("events.sig", signature, "application/octet-stream"),
        },
    )


class ApiIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.tmp = Path(self._temporary.name)
        config_dir = self.tmp / "config"
        config_dir.mkdir()
        self.config_path = write_config(config_dir)
        self.db_path = self.tmp / "alerts.sqlite3"
        self.staging = self.tmp / "staging"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_probe_config_and_valid_duplicate_batch(self):
        rows = [
            event(event_id="evt-1", rule="first"),
            event(event_id="evt-2", host="db-01.example.internal", rule="second"),
            event(event_id="evt-1", rule="first"),  # byte-for-byte identical duplicate
        ]
        payload = make_jsonl(rows)
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            probes_response = client.get("/api/probes")
            self.assertEqual(probes_response.status_code, 200)
            probes = probes_response.json()["probes"]
            self.assertEqual([p["probe_id"] for p in probes], ["probe-alpha", "probe-beta"])
            self.assertEqual(
                probes[0]["authorized_hosts"],
                ["db-01.example.internal", "web-01.example.internal"],
            )

            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["status"], "committed")
            self.assertEqual(result["total_lines"], 3)
            self.assertEqual(result["imported_lines"], 2)
            self.assertEqual(result["skipped_lines"], 1)
            self.assertEqual(client.get("/api/alerts").json()["total"], 2)

            # Re-submitting the same batch skips every row against the DB too.
            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["imported_lines"], 0)
            self.assertEqual(result["skipped_lines"], 3)
            self.assertEqual(client.get("/api/alerts").json()["total"], 2)

    def test_tampered_file_fails_signature_and_imports_no_alerts(self):
        payload = make_jsonl([event(rule="original")])
        signature = sign(Keys.alpha_key, payload)
        tampered = payload.replace(b"original", b"tampered")

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client, probe_id="probe-alpha", payload=tampered, signature=signature
            )
            self.assertEqual(response.status_code, 400, response.text)
            self.assertEqual(response.json()["detail"]["code"], "signature_invalid")
            self.assertEqual(client.get("/api/alerts").json()["total"], 0)
            imports = client.get("/api/imports").json()["items"]
            self.assertEqual(imports[0]["status"], "failed")
            self.assertEqual(imports[0]["failure_code"], "signature_invalid")

    def test_probe_mismatch_and_unauthorized_host_are_rejected(self):
        beta_payload = make_jsonl([event(probe_id="probe-beta", host="web-02.example.internal")])
        beta_signature = sign(Keys.beta_key, beta_payload)
        alpha_payload = make_jsonl([event(host="attacker.example.internal")])
        alpha_signature = sign(Keys.alpha_key, alpha_payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            mismatch = upload(
                client,
                probe_id="probe-alpha",
                payload=beta_payload,
                signature=beta_signature,
            )
            self.assertEqual(mismatch.status_code, 400, mismatch.text)
            self.assertEqual(mismatch.json()["detail"]["code"], "probe_mismatch")
            self.assertEqual(mismatch.json()["detail"]["line"], 1)

            host = upload(
                client, probe_id="probe-alpha", payload=alpha_payload, signature=alpha_signature
            )
            self.assertEqual(host.status_code, 403, host.text)
            self.assertEqual(host.json()["detail"]["code"], "host_unauthorized")
            self.assertEqual(client.get("/api/alerts").json()["total"], 0)

    def test_line_and_file_limits(self):
        long_row = event(rule="x" * 5000)
        payload = make_jsonl([long_row])
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 413, response.text)
            self.assertEqual(response.json()["detail"]["code"], "line_too_large")
            self.assertEqual(client.get("/api/alerts").json()["total"], 0)

    def test_duplicate_conflict_within_batch_rejects_everything(self):
        rows = [
            event(event_id="evt-1", rule="same"),
            event(event_id="evt-2", rule="new"),
            event(event_id="evt-1", rule="different"),
        ]
        payload = make_jsonl(rows)
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(response.json()["detail"]["code"], "duplicate_conflict")
            self.assertEqual(response.json()["detail"]["line"], 3)
            self.assertEqual(client.get("/api/alerts").json()["total"], 0)

    def test_existing_duplicate_conflict_rolls_back_new_rows(self):
        first_payload = make_jsonl(
            [event(event_id="evt-1", rule="original"), event(event_id="evt-2", rule="two")]
        )
        first_signature = sign(Keys.alpha_key, first_payload)
        second_rows = [
            event(event_id="evt-1", rule="changed"),
            event(event_id="evt-3", rule="must-not-appear"),
        ]
        second_payload = make_jsonl(second_rows)
        second_signature = sign(Keys.alpha_key, second_payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            first = upload(
                client, probe_id="probe-alpha", payload=first_payload, signature=first_signature
            )
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(client.get("/api/alerts").json()["total"], 2)

            second = upload(
                client, probe_id="probe-alpha", payload=second_payload, signature=second_signature
            )
            self.assertEqual(second.status_code, 409, second.text)
            self.assertEqual(second.json()["detail"]["code"], "duplicate_conflict")

            alerts = client.get("/api/alerts?page_size=100").json()
            self.assertEqual(alerts["total"], 2)
            self.assertEqual(
                {item["event_id"] for item in alerts["items"]},
                {"evt-1", "evt-2"},
            )

    def test_identical_existing_events_are_skipped(self):
        rows = [event(event_id="evt-1", rule="a"), event(event_id="evt-2", rule="b")]
        payload = make_jsonl(rows)
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            first = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(first.status_code, 200, first.text)
            second = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(second.json()["imported_lines"], 0)
            self.assertEqual(second.json()["skipped_lines"], 2)

    def test_pagination_and_probe_filter(self):
        alpha_rows = [event(event_id=f"a-{index:02d}", time_value=1793000000 + index) for index in range(15)]
        beta_rows = [event(probe_id="probe-beta", event_id=f"b-{index:02d}", host="web-02.example.internal", time_value=1793000100 + index) for index in range(8)]
        alpha_payload = make_jsonl(alpha_rows)
        beta_payload = make_jsonl(beta_rows)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            for probe, data, key in (
                ("probe-alpha", alpha_payload, Keys.alpha_key),
                ("probe-beta", beta_payload, Keys.beta_key),
            ):
                response = upload(
                    client, probe_id=probe, payload=data, signature=sign(key, data)
                )
                self.assertEqual(response.status_code, 200, response.text)

            page1 = client.get("/api/alerts?page=1&page_size=10").json()
            page2 = client.get("/api/alerts?page=2&page_size=10").json()
            page3 = client.get("/api/alerts?page=3&page_size=10").json()
            self.assertEqual(page1["total"], 23)
            self.assertEqual(page1["pages"], 3)
            self.assertEqual(len(page1["items"]), 10)
            self.assertEqual(len(page2["items"]), 10)
            self.assertEqual(len(page3["items"]), 3)
            self.assertTrue(page1["has_next"])
            self.assertFalse(page3["has_next"])

            filtered = client.get("/api/alerts?probe_id=probe-beta&page_size=100").json()
            self.assertEqual(filtered["total"], 8)
            self.assertTrue(all(item["probe_id"] == "probe-beta" for item in filtered["items"]))

    def test_pss_salt_length_must_be_exactly_32(self):
        payload = make_jsonl([event(event_id="evt-salt")])
        wrong_salt_signature = sign(Keys.alpha_key, payload, salt_length=31)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client,
                probe_id="probe-alpha",
                payload=payload,
                signature=wrong_salt_signature,
            )
            self.assertEqual(response.status_code, 400, response.text)
            self.assertEqual(response.json()["detail"]["code"], "signature_invalid")
            self.assertEqual(client.get("/api/alerts").json()["total"], 0)

    def test_exact_4kib_line_is_accepted(self):
        row = event(event_id="evt-boundary", rule="")
        without_rule = len(json.dumps(row, separators=(",", ":")))
        row["rule"] = "x" * (4096 - without_rule)
        payload = make_jsonl([row])
        self.assertEqual(len(payload.rstrip(b"\n")), 4096)
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["imported_lines"], 1)

    def test_base64_signature_is_accepted(self):
        payload = make_jsonl([event(event_id="evt-b64")])
        signature = base64.b64encode(sign(Keys.alpha_key, payload))

        with app_client(self.config_path, self.db_path, self.staging) as client:
            response = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["imported_lines"], 1)


class RevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.tmp = Path(self._temporary.name)
        config_dir = self.tmp / "config"
        config_dir.mkdir()
        self.config_path = write_config(config_dir)
        self.db_path = self.tmp / "alerts.sqlite3"
        self.staging = self.tmp / "staging"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_revoke_blocks_import_and_survives_restart(self):
        payload = make_jsonl([event(event_id="evt-before-revoke")])
        signature = sign(Keys.alpha_key, payload)

        with app_client(self.config_path, self.db_path, self.staging) as client:
            first = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(first.status_code, 200, first.text)

            revoked = client.post("/api/probes/probe-alpha/revoke")
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertTrue(revoked.json()["revoked"])

            blocked = upload(
                client, probe_id="probe-alpha", payload=payload, signature=signature
            )
            self.assertEqual(blocked.status_code, 409, blocked.text)
            self.assertEqual(blocked.json()["detail"]["code"], "probe_revoked")
            # Existing history remains auditable.
            self.assertEqual(client.get("/api/alerts").json()["total"], 1)

        # A fresh process/app lifecycle reloads configuration but must not
        # clear revocations persisted in SQLite.
        with app_client(self.config_path, self.db_path, self.staging) as client:
            probes = {p["probe_id"]: p for p in client.get("/api/probes").json()["probes"]}
            self.assertTrue(probes["probe-alpha"]["revoked"])
            self.assertFalse(probes["probe-beta"]["revoked"])

    def test_two_app_instances_share_revocation_state(self):
        alpha_payload = make_jsonl([event(event_id="evt-alpha")])
        alpha_signature = sign(Keys.alpha_key, alpha_payload)
        beta_payload = make_jsonl(
            [event(probe_id="probe-beta", event_id="evt-beta", host="web-02.example.internal")]
        )
        beta_signature = sign(Keys.beta_key, beta_payload)

        with app_client(self.config_path, self.db_path, self.staging) as client_a:
            with app_client(self.config_path, self.db_path, self.staging) as client_b:
                revoked = client_b.post("/api/probes/probe-alpha/revoke")
                self.assertEqual(revoked.status_code, 200, revoked.text)

                blocked = upload(
                    client_a,
                    probe_id="probe-alpha",
                    payload=alpha_payload,
                    signature=alpha_signature,
                )
                self.assertEqual(blocked.status_code, 409, blocked.text)
                self.assertEqual(blocked.json()["detail"]["code"], "probe_revoked")

                allowed = upload(
                    client_a,
                    probe_id="probe-beta",
                    payload=beta_payload,
                    signature=beta_signature,
                )
                self.assertEqual(allowed.status_code, 200, allowed.text)
                self.assertEqual(client_b.get("/api/alerts").json()["total"], 1)

    def test_revoke_succeeds_while_import_is_still_reading_and_batch_fails(self):
        """The business write lock is not held during the streaming phase."""

        probes = load_probe_config(self.config_path)
        initialize_storage(self.db_path, probes)
        probe = probes["probe-alpha"]
        payload = make_jsonl([event(event_id="evt-slow", rule="slow")])
        signature = sign(Keys.alpha_key, payload)

        class BlockingFile(io.BytesIO):
            def __init__(self, data: bytes):
                super().__init__(data)
                self.started = threading.Event()
                self.release = threading.Event()
                self._blocked = False

            def read(self, size=-1):
                if not self._blocked:
                    self._blocked = True
                    self.started.set()
                    self.release.wait(timeout=10)
                return super().read(size)

        slow_file = BlockingFile(payload)
        errors: list[Exception] = []
        results: list[object] = []

        def worker():
            try:
                results.append(
                    ingest_batch(
                        db_path=self.db_path,
                        staging_dir=self.staging,
                        probe=probe,
                        events_file=slow_file,
                        signature_raw=signature,
                        file_name="slow.jsonl",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - asserted below
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(slow_file.started.wait(timeout=5))

        started_at = time.monotonic()
        revocation = revoke_probe(self.db_path, "probe-alpha")
        elapsed = time.monotonic() - started_at
        self.assertIsNotNone(revocation)
        self.assertLess(elapsed, 2.0, "revocation waited for the streaming import")

        slow_file.release.set()
        thread.join(timeout=15)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], IngestError)
        self.assertEqual(errors[0].code, "probe_revoked")
        self.assertEqual(results, [])
        self.assertEqual(count_alerts(self.db_path), 0)

    def test_revocation_table_is_never_reset_by_config_sync(self):
        probes = load_probe_config(self.config_path)
        initialize_storage(self.db_path, probes)
        revoke_probe(self.db_path, "probe-alpha")
        self.assertTrue(list_probes(self.db_path)[0]["revoked"])

        # Simulate a later startup with a changed configuration/public key.
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["probes"][0]["authorized_hosts"].append("new-host.example.internal")
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        initialize_storage(self.db_path, load_probe_config(self.config_path))

        by_id = {probe["probe_id"]: probe for probe in list_probes(self.db_path)}
        self.assertTrue(by_id["probe-alpha"]["revoked"])
        self.assertEqual(
            by_id["probe-alpha"]["authorized_hosts"],
            ["db-01.example.internal", "new-host.example.internal", "web-01.example.internal"],
        )


class BundledSampleTests(unittest.TestCase):
    def test_bundled_valid_and_tampered_samples(self):
        root = Path(__file__).resolve().parent.parent
        config_path = root / "config" / "probes.json"
        valid = (root / "examples" / "probe-alpha-valid.jsonl").read_bytes()
        signature = (root / "examples" / "probe-alpha-valid.sig").read_bytes()
        tampered = (root / "examples" / "probe-alpha-tampered.jsonl").read_bytes()

        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            with app_client(config_path, tmp / "alerts.sqlite3", tmp / "staging") as client:
                valid_response = upload(
                    client, probe_id="probe-alpha", payload=valid, signature=signature
                )
                self.assertEqual(valid_response.status_code, 200, valid_response.text)
                self.assertEqual(valid_response.json()["imported_lines"], 5)
                self.assertEqual(valid_response.json()["skipped_lines"], 1)

                tampered_response = upload(
                    client, probe_id="probe-alpha", payload=tampered, signature=signature
                )
                self.assertEqual(tampered_response.status_code, 400, tampered_response.text)
                self.assertEqual(
                    tampered_response.json()["detail"]["code"], "signature_invalid"
                )
                self.assertEqual(client.get("/api/alerts").json()["total"], 5)


if __name__ == "__main__":
    unittest.main()
