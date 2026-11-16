#!/usr/bin/env python3
"""End-to-end self test for the research data archive.

Spins up the real witness and archive uvicorn processes against temp
directories (stand-ins for the two Docker volumes) and exercises:

  1. health of both services
  2. normal upload: receipt issued, signature verifies, catalog + download
  3. idempotent re-upload (same batch/content reuses receipt, no duplication)
  4. different content under same key is rejected
  5. >2 MiB upload is refused
  6. concurrent double-window retries never double-archive, and distinct
     batches uploading in parallel each archive exactly once (no global lock)
  7. crash after witness acceptance -> restart -> automatic reconciliation
  7b. witness receipts and signatures survive a full restart (persistent
      volume), no data loss
  8. witness unreachable -> "pending/待核", never silently re-submitted
  9. verification page detects tampering, missing file, catalog omission
 10. forged receipts (foreign Ed25519 key) are rejected by the fixed key
 11. verification fails (503) while witness is down

Run:  python3 scripts/self_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
HOST = "127.0.0.1"


def free_port() -> int:
    """Pick an ephemeral free port (orphaned processes make fixed ports
    unsafe in sandboxes where kill(2) is blocked)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
        sk.bind((HOST, 0))
        return sk.getsockname()[1]


PORT_W = free_port()
PORT_A = free_port()
PORT_A_ISOLATED = free_port()

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def wait_down(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                time.sleep(0.3)
        except OSError:
            return True
    return False


def req(method: str, port: int, path: str, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(raw.decode())
    except json.JSONDecodeError:
        return resp.status, raw


def multipart(fields: dict[str, str], file_field: str, filename: str,
              content: bytes) -> tuple[bytes, dict]:
    boundary = "----selftest" + uuid.uuid4().hex
    lines = []
    for name, value in fields.items():
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        lines.append(value.encode() + b"\r\n")
    lines.append(f"--{boundary}\r\n".encode())
    lines.append(
        f'Content-Disposition: form-data; name="{file_field}"; '
        f'filename="{filename}"\r\n'.encode())
    lines.append(b"Content-Type: application/octet-stream\r\n\r\n")
    lines.append(content + b"\r\n")
    lines.append(f"--{boundary}--\r\n".encode())
    return b"".join(lines), {"Content-Type": f"multipart/form-data; "
                                             f"boundary={boundary}"}


def upload(port: int, batch: str, filename: str, content: bytes):
    body, headers = multipart(
        {"filename": filename}, "file", filename, content)
    return req("POST", port,
               f"/api/batches/{batch}/files", body, headers)


class Harness:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="archive-selftest-"))
        self.keys = self.tmp / "keys"
        self.wdata = self.tmp / "witness"
        self.adata = self.tmp / "archive"
        for d in (self.keys, self.wdata, self.adata):
            d.mkdir(parents=True)
        self.procs: list[subprocess.Popen] = []

    def gen_keys(self):
        priv = self.keys / "witness_ed25519.pem"
        pub = self.keys / "witness_ed25519.pub.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(priv)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout",
                        "-out", str(pub)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_witness(self):
        env = os.environ.copy()
        env.update({"WITNESS_DB": str(self.wdata / "witness.db"),
                    "WITNESS_KEY": str(self.keys / "witness_ed25519.pem")})
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "witness.main:app",
             "--host", HOST, "--port", str(PORT_W)],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append((p, PORT_W, "/__selftest_shutdown"))
        return p

    def start_archive(self, port=PORT_A, witness_port=PORT_W,
                      crash_marker: Path | None = None):
        env = os.environ.copy()
        env.update({
            "ARCHIVE_DB": str(self.adata / f"archive-{port}.db"),
            "ARCHIVE_STORAGE": str(self.adata / f"originals-{port}"),
            "ARCHIVE_PUBLIC_KEY":
                str(self.keys / "witness_ed25519.pub.pem"),
            "WITNESS_URL": f"http://{HOST}:{witness_port}",
            "ARCHIVE_CRASH_MARKER": str(
                crash_marker or (self.adata / f"crash-{port}.flag")),
        })
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "archive.main:app",
             "--host", HOST, "--port", str(port)],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append((p, port, "/__selftest_shutdown"))
        return p

    def shutdown_port(self, port: int) -> None:
        """Graceful shutdown through the test-only HTTP endpoint."""
        try:
            req("POST", port, "/__selftest_shutdown")
        except OSError:
            pass

    def cleanup(self):
        # Signals are blocked in this CI sandbox; stop via HTTP instead.
        for _, port, path in list(self.procs):
            try:
                req("POST", port, path)
            except OSError:
                pass
        deadline = time.time() + 8
        while time.time() < deadline:
            alive = [p for p, _, _ in self.procs if p.poll() is None]
            if not alive:
                break
            time.sleep(0.3)
        shutil.rmtree(self.tmp, ignore_errors=True)


def main() -> int:
    h = Harness()
    try:
        h.gen_keys()
        h.start_witness()
        h.start_archive()
        if not wait_port(PORT_W) or not wait_port(PORT_A):
            check("services start", False, "ports never came up")
            return 1
        check("services start", True,
              f"witness:{PORT_W} archive:{PORT_A}")

        # 1. health
        s, w = req("GET", PORT_W, "/health")
        check("witness health + key fingerprint",
              s == 200 and len(w["public_key_fingerprint"]) == 64)
        s, a = req("GET", PORT_A, "/api/batches")
        check("archive health endpoint", s == 200)

        # 1b. empty witness list must not be reported as "passed"
        s, empty_report = req("GET", PORT_A, "/api/verify")
        check("empty witness list is not a silent pass",
              s == 200 and empty_report["passed"] is False
              and empty_report["empty"] is True
              and empty_report["witness_reachable"] is True)

        # 2. normal upload
        b1 = "BATCH-001"
        content = b"site,temp_c,ph\nA,21.4,7.1\nB,19.8,6.8\n"
        s, r = upload(PORT_A, b1, "readings.csv", content)
        ok = (s == 200 and r["result"] == "registered"
              and r["batch"]["status"] == "complete"
              and r["batch"]["files"][0]["receipt"]["algorithm"] == "Ed25519")
        check("normal upload registers with Ed25519 receipt", ok,
              f"http={s}")
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b1}/download/readings.csv")
        check("download open only after full success",
              s == 200 and dl == content)
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("witness independently persisted length+SHA256",
              s == 200 and witness_list["count"] == 1
              and witness_list["items"][0]["length"] == len(content))

        # 3. idempotent re-upload
        s, r = upload(PORT_A, b1, "readings.csv", content)
        check("same batch+content reuses receipt (idempotent)",
              s == 200 and r["result"] == "already_registered")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("idempotent retry creates no duplicate witness record",
              witness_list["count"] == 1)

        # 4. conflicting content rejected
        s, r = upload(PORT_A, b1, "readings.csv", content + b"TAMPERED\n")
        check("different content under same key rejected (409)",
              s == 409, str(r)[:120])
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b1}/download/readings.csv")
        check("rejected conflict leaves witnessed original intact",
              s == 200 and dl == content)

        # 5. size limit
        big = b"x" * (2 * 1024 * 1024 + 1)
        s, r = upload(PORT_A, "BATCH-BIG", "big.bin", big)
        check(">2 MiB upload refused", s == 413, f"http={s}")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("oversized file never reached witness",
              all(it["batch_id"] != "BATCH-BIG"
                  for it in witness_list["items"]))

        # 6. concurrent double-window retries
        b2 = "BATCH-CONC"
        c2 = b"concurrent-window-content-" + uuid.uuid4().hex.encode()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(upload, PORT_A, b2, "data.txt", c2)
                    for _ in range(2)]
            responses = [f.result() for f in futs]
        statuses = sorted(s for s, _ in responses)
        s, witness_list = req("GET", PORT_W, "/receipts")
        dupes = [it for it in witness_list["items"]
                 if it["batch_id"] == b2 and it["filename"] == "data.txt"]
        s, batch = req("GET", PORT_A, f"/api/batches/{b2}")
        check("concurrent retries: no double archive",
              len(dupes) == 1 and batch["file_count"] == 1
              and batch["status"] == "complete",
              f"http statuses={statuses}")

        # 6b. distinct batches in parallel: no global lock, each independent
        import concurrent.futures as cf
        cross = [(f"BATCH-X{i}", f"f{i}.csv",
                  b"cross-batch-" + uuid.uuid4().hex.encode())
                 for i in range(4)]
        with cf.ThreadPoolExecutor(max_workers=4) as ex:
            cross_resp = list(ex.map(
                lambda args: upload(PORT_A, *args), cross))
        cross_ok = all(s == 200 and r["result"] == "registered"
                       for s, r in cross_resp)
        cross_names = {b for b, _, _ in cross}
        s, witness_list = req("GET", PORT_W, "/receipts")
        cross_records = {b: 0 for b in cross_names}
        for it in witness_list["items"]:
            if it["batch_id"] in cross_records:
                cross_records[it["batch_id"]] += 1
        check("parallel distinct batches each archive exactly once",
              cross_ok and all(v == 1 for v in cross_records.values())
              and len(cross_records) == 4,
              f"records={cross_records}")

        # 7. crash after acceptance, restart, reconcile
        b3 = "BATCH-CRASH"
        c3 = b"crash-recovery-content"
        # Arm through the admin API (marker lives in the archive volume).
        s, r = req("POST", PORT_A, "/api/admin/arm-crash")
        armed = s == 200 and r["armed"]
        check("crash marker armed", armed)
        try:
            s, r = upload(PORT_A, b3, "f.csv", c3)
            crash_detail = f"http={s}"
        except OSError as exc:
            # The process exits mid-request; the connection dying is expected.
            crash_detail = f"connection reset as expected ({exc.__class__.__name__})"
        check("upload attempted across crash point", True, crash_detail)
        check("archive process actually exited",
              wait_down(PORT_A, 10), f"port {PORT_A} closed")
        # Restart with identical env (simulates Docker restart policy).
        restart_env = os.environ.copy()
        restart_env.update({
            "ARCHIVE_DB": str(h.adata / f"archive-{PORT_A}.db"),
            "ARCHIVE_STORAGE": str(h.adata / f"originals-{PORT_A}"),
            "ARCHIVE_PUBLIC_KEY":
                str(h.keys / "witness_ed25519.pub.pem"),
            "WITNESS_URL": f"http://{HOST}:{PORT_W}",
            "ARCHIVE_CRASH_MARKER": str(h.adata / f"crash-{PORT_A}.flag"),
        })
        p2 = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "archive.main:app",
             "--host", HOST, "--port", str(PORT_A)],
            cwd=ROOT, env=restart_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h.procs.append((p2, PORT_A, "/__selftest_shutdown"))
        check("archive restarts and reconnects", wait_port(PORT_A))
        # Startup reconciliation must query the witness and finish the batch.
        deadline = time.time() + 15
        batch = {}
        while time.time() < deadline:
            s, batch = req("GET", PORT_A, f"/api/batches/{b3}")
            if batch.get("status") == "complete":
                break
            time.sleep(0.5)
        check("restart auto-reconciles batch from witness receipt",
              batch.get("status") == "complete",
              f"status={batch.get('status')}")
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b3}/download/f.csv")
        check("reconciled original downloadable and byte-identical",
              s == 200 and dl == c3)
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("reconciliation did not re-submit (no duplicate)",
              len([it for it in witness_list["items"]
                   if it["batch_id"] == b3]) == 1)

        # 7b. witness volume survives a full restart (persistent storage)
        persisted_count = witness_list["count"]
        h.shutdown_port(PORT_W)
        check("witness stopped for restart-persistence test",
              wait_down(PORT_W, 10))
        wp = h.start_witness()  # same WITNESS_DB path -> same volume
        check("witness restarts on its persistent volume", wait_port(PORT_W))
        s, after = req("GET", PORT_W, "/receipts")
        check("witness receipts survive restart (persistent volume)",
              s == 200 and after["count"] == persisted_count
              and persisted_count >= 1,
              f"before={persisted_count} after={after['count']}")
        # A stored receipt must still verify after the restart.
        from common.receipt import verify_envelope as _ve, \
            load_public_key as _lpk
        any_env = after["items"][0]["receipt"]
        ok_sig, _ = _ve(_lpk(h.keys / "witness_ed25519.pub.pem"), any_env)
        check("stored receipt signature still valid after restart", ok_sig)

        # 8. witness unreachable -> pending, not blind re-submit
        isolated_marker = h.adata / "crash-iso.flag"
        h.start_archive(port=PORT_A_ISOLATED, witness_port=8999,
                        crash_marker=isolated_marker)
        wait_port(PORT_A_ISOLATED)
        b4 = "BATCH-DISCONNECT"
        c4 = b"offline-buffer-content"
        s, r = upload(PORT_A_ISOLATED, b4, "g.csv", c4)
        check("witness unreachable => 202 pending (待核)",
              s == 202 and r["result"] == "pending"
              and r["reason"] == "witness_unreachable", f"http={s}")
        s, batch = req("GET", PORT_A_ISOLATED, f"/api/batches/{b4}")
        check("pending batch not reported complete / download closed",
              batch["status"] == "pending"
              and batch["files"][0]["status"] == "pending")
        s, _ = req("GET", PORT_A_ISOLATED,
                    f"/api/batches/{b4}/download/g.csv")
        check("download refused while pending", s in (404, 409))
        s, r = req("POST", PORT_A_ISOLATED, "/api/reconcile")
        check("reconcile while witness down keeps pending, never resubmits",
              s == 200 and r["results"][0]["state"] == "pending"
              and r["results"][0]["reason"] == "witness_unreachable")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("witness still has no record of disconnected batch",
              all(it["batch_id"] != b4 for it in witness_list["items"]))

        # 9. verification against the witness's issued list
        s, report = req("GET", PORT_A, "/api/verify")
        check("clean verification passes from witness list",
              s == 200 and report["passed"] is True
              and report["witness_reachable"] is True,
              f"receipts={report.get('receipt_count')}")

        # 9a. tamper a stored original
        target = (h.adata / f"originals-{PORT_A}" / b1 / "readings.csv")
        original_bytes = target.read_bytes()
        target.write_bytes(original_bytes + b"EXTRA")
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for f in report["batches"][0]["files"]
                    for p in f["problems"]]
        check("verification detects tampered original",
              not report["passed"] and "tampered_original" in problems,
              str(problems))
        target.write_bytes(original_bytes)  # restore

        # 9b. remove a local original (missing file)
        target = (h.adata / f"originals-{PORT_A}" / b2 / "data.txt")
        saved = target.read_bytes()
        target.unlink()
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for b in report["batches"] for f in b["files"]
                    for p in f["problems"]]
        check("verification detects missing original",
              "missing_original" in problems)
        target.write_bytes(saved)  # restore

        # 9c. catalog omission: keep original+witness receipt, drop catalog row
        import sqlite3
        db_path = h.adata / f"archive-{PORT_A}.db"
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM files WHERE batch_id=? AND filename=?",
                     (b2, "data.txt"))
        conn.commit()
        conn.close()
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for b in report["batches"] for f in b["files"]
                    for p in f["problems"]]
        check("verification detects catalog omission (目录漏登)",
              "catalog_missing" in problems)

        # 9d. a forged receipt (attacker's own Ed25519 key) must not verify
        # against the fixed public key pinned in the archiver.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        from common.receipt import (
            build_envelope, load_private_key, load_public_key,
            verify_envelope)
        fixed_pub = load_public_key(h.keys / "witness_ed25519.pub.pem")
        forged = build_envelope(Ed25519PrivateKey.generate(),
                                b1, "readings.csv", len(content),
                                "0" * 64)
        ok_forge, err_forge = verify_envelope(fixed_pub, forged)
        check("forged receipt from foreign key rejected",
              ok_forge is False, err_forge or "")
        genuine = build_envelope(
            load_private_key(h.keys / "witness_ed25519.pem"),
            b1, "readings.csv", len(content), "0" * 64)
        ok_real, _ = verify_envelope(fixed_pub, genuine)
        check("genuine witness receipt verifies against fixed key",
              ok_real is True)

        # 10. witness down => verification must not pass
        h.shutdown_port(PORT_W)
        check("witness process exits for the outage demo",
              wait_down(PORT_W, 10), f"port {PORT_W} closed")
        s, report = req("GET", PORT_A, "/api/verify")
        check("witness unreachable => verification 503, never passed",
              s == 503 and report["passed"] is False
              and report["witness_reachable"] is False)

    finally:
        h.cleanup()

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 64)
    print(f"self test summary: {len(results) - len(failed)}/"
          f"{len(results)} passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print("  -", n)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
