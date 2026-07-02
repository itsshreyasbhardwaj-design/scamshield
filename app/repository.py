from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .config import Settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class ScanRecord:
    content_hash: str
    type: str
    score: int
    verdict: str
    language: str
    user_id: Optional[str] = None
    signals: List[str] = field(default_factory=list)
    raw: Optional[str] = None                 # populated ONLY on explicit opt-in
    id: str = field(default_factory=_new_id)
    created_at: str = field(default_factory=_now)


@dataclass
class ReportRecord:
    pattern: str                              # redacted before it reaches here
    category: str
    user_id: Optional[str] = None
    upvotes: int = 0
    status: str = "pending"                   # moderated before public display
    id: str = field(default_factory=_new_id)
    created_at: str = field(default_factory=_now)


class InMemoryRepository:
    """Offline default. Simulates row-level security by scoping every read to the
    caller's user_id — mirrors the RLS policies enforced by Supabase in prod."""

    def __init__(self) -> None:
        self._scans: List[ScanRecord] = []
        self._reports: List[ReportRecord] = []

    def save_scan(self, rec: ScanRecord) -> str:
        self._scans.append(rec)
        return rec.id

    def list_scans(self, user_id: str) -> List[ScanRecord]:
        rows = [s for s in self._scans if s.user_id == user_id]
        return sorted(rows, key=lambda s: s.created_at, reverse=True)

    def add_report(self, rec: ReportRecord) -> str:
        self._reports.append(rec)
        return rec.id

    def approved_reports(self) -> List[ReportRecord]:
        return [r for r in self._reports if r.status == "approved"]

    def delete_user_data(self, user_id: str) -> int:
        before = len(self._scans) + len(self._reports)
        self._scans = [s for s in self._scans if s.user_id != user_id]
        self._reports = [r for r in self._reports if r.user_id != user_id]
        return before - (len(self._scans) + len(self._reports))


class SupabaseRepository:
    """Live store via Supabase REST (service-role key, server-side only).
    RLS is enforced in Postgres; we additionally scope by user_id here. Never
    ship the service-role key to the client."""

    def __init__(self, settings: Settings, client=None) -> None:
        self._base = settings.supabase_url.rstrip("/") + "/rest/v1"
        self._key = settings.supabase_service_role_key
        self._client = client

    def _http(self):
        if self._client is None:                       # create once and reuse (no per-call leak)
            import httpx
            self._client = httpx.Client(
                timeout=8.0,
                headers={"apikey": self._key, "Authorization": f"Bearer {self._key}",
                         "Content-Type": "application/json"},
            )
        return self._client

    def save_scan(self, rec: ScanRecord) -> str:
        row = {"id": rec.id, "user_id": rec.user_id, "content_hash": rec.content_hash,
               "type": rec.type, "score": rec.score, "verdict": rec.verdict,
               "signals": rec.signals, "language": rec.language,
               "created_at": rec.created_at}
        if rec.raw is not None:
            row["raw_content"] = rec.raw
        self._http().post(f"{self._base}/scans", json=row).raise_for_status()
        return rec.id

    def list_scans(self, user_id: str) -> List[ScanRecord]:
        r = self._http().get(f"{self._base}/scans", params={
            "user_id": f"eq.{user_id}", "order": "created_at.desc", "limit": "100"})
        r.raise_for_status()
        return [ScanRecord(content_hash=x.get("content_hash", ""), type=x.get("type", ""),
                           score=x.get("score", 0), verdict=x.get("verdict", ""),
                           language=x.get("language", "en"), user_id=x.get("user_id"),
                           signals=x.get("signals", []), id=x.get("id", ""),
                           created_at=x.get("created_at", "")) for x in r.json()]

    def add_report(self, rec: ReportRecord) -> str:
        row = {"id": rec.id, "user_id": rec.user_id, "pattern": rec.pattern,
               "category": rec.category, "upvotes": rec.upvotes,
               "status": rec.status, "created_at": rec.created_at}
        self._http().post(f"{self._base}/reports", json=row).raise_for_status()
        return rec.id

    def approved_reports(self) -> List[ReportRecord]:
        r = self._http().get(f"{self._base}/reports", params={
            "status": "eq.approved", "order": "upvotes.desc", "limit": "100"})
        r.raise_for_status()
        return [ReportRecord(pattern=x.get("pattern", ""), category=x.get("category", "other"),
                             user_id=x.get("user_id"), upvotes=x.get("upvotes", 0),
                             status=x.get("status", "approved"), id=x.get("id", ""),
                             created_at=x.get("created_at", "")) for x in r.json()]

    def delete_user_data(self, user_id: str) -> int:
        c = self._http()
        total = 0
        for table in ("scans", "reports"):
            r = c.delete(f"{self._base}/{table}", params={"user_id": f"eq.{user_id}"},
                         headers={"Prefer": "count=exact"})
            # PostgREST returns the affected count in Content-Range: "0-4/5" or "*/5"
            cr = r.headers.get("content-range", "")
            if "/" in cr and cr.split("/")[-1].isdigit():
                total += int(cr.split("/")[-1])
        return total


def get_repository(settings: Settings):
    if settings.database_mode == "supabase":
        return SupabaseRepository(settings)
    return InMemoryRepository()
