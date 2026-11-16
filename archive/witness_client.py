"""HTTP client for the independent witness service."""
from __future__ import annotations

from typing import Any

import httpx


class WitnessUnreachable(RuntimeError):
    """The witness cannot be reached; the request must NOT be retried blind."""


class WitnessConflict(RuntimeError):
    """The witness already holds different content under the same key."""

    def __init__(self, detail: dict[str, Any]):
        super().__init__(detail.get("message", "content conflict"))
        self.detail = detail


class WitnessClient:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self._base, timeout=self._timeout)

    def health(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get("/health")
            r.raise_for_status()
            return r.json()

    def submit(self, batch_id: str, filename: str, content: bytes,
               sha256: str) -> dict[str, Any]:
        """Submit one original. Returns the witness envelope response."""
        try:
            with self._client() as c:
                r = c.post(
                    "/receipts",
                    data={"batch_id": batch_id, "filename": filename},
                    files={"file": (filename, content,
                                    "application/octet-stream")},
                )
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        if r.status_code == 409:
            raise WitnessConflict(r.json())
        if r.status_code >= 400:
            raise RuntimeError(
                f"witness rejected upload (HTTP {r.status_code}): {r.text}"
            )
        return r.json()

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        try:
            with self._client() as c:
                r = c.get(f"/batches/{batch_id}")
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        if r.status_code == 404:
            return {"batch_id": batch_id, "count": 0, "items": []}
        r.raise_for_status()
        return r.json()

    def list_receipts(self) -> dict[str, Any]:
        try:
            with self._client() as c:
                r = c.get("/receipts")
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        r.raise_for_status()
        return r.json()
