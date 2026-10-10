"""Persistencia em SQLite: lista de confiaveis e estado de processamento."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_WILDCARDS = set("*?%[]")


@dataclass(frozen=True)
class TrustEntry:
    value: str
    kind: str  # "address" | "domain"
    note: str
    added_at: datetime  # UTC aware


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(db_path)


def _to_utc(when: datetime) -> datetime:
    if when.tzinfo is None:
        return when.replace(tzinfo=UTC)
    return when.astimezone(UTC)


def _parse_domain(domain: str) -> str:
    if not domain or "." not in domain:
        raise ValueError("dominio invalido: precisa conter ponto (ex.: empresa.com)")
    labels = domain.split(".")
    if any(not label for label in labels):
        raise ValueError("dominio invalido: rotulo vazio")
    return domain


def _normalize(value: str) -> tuple[str, str]:
    """Retorna (valor normalizado, tipo). Levanta ValueError se invalido."""
    v = (value or "").strip().lower()
    if not v:
        raise ValueError("valor vazio")
    if any(c.isspace() for c in v):
        raise ValueError("valor nao pode conter espacos")
    if any(c in _WILDCARDS for c in v):
        raise ValueError("curingas nao sao permitidos")
    if v.count("@") > 1:
        raise ValueError("valor com mais de um '@'")
    if "@" in v:
        local, domain = v.split("@")
        if not local:
            return _parse_domain(domain), "domain"
        return f"{local}@{_parse_domain(domain)}", "address"
    return _parse_domain(v), "domain"


def _split_address(address: str) -> tuple[str, str] | None:
    a = (address or "").strip().lower()
    if a.count("@") != 1 or any(c.isspace() for c in a):
        return None
    local, domain = a.split("@")
    if not local or not domain or "." not in domain:
        return None
    if any(not label for label in domain.split(".")):
        return None
    return local, domain


class TrustStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        with closing(_connect(db_path)) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS trusted ("
                "value TEXT PRIMARY KEY, kind TEXT NOT NULL, "
                "note TEXT NOT NULL, added_at TEXT NOT NULL)"
            )

    def add(self, value: str, note: str = "") -> TrustEntry:
        normalized, kind = _normalize(value)
        with closing(_connect(self._db_path)) as conn, conn:
            row = conn.execute(
                "SELECT added_at FROM trusted WHERE value = ?", (normalized,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE trusted SET note = ? WHERE value = ?", (note, normalized)
                )
                added_at = datetime.fromisoformat(row[0])
            else:
                added_at = datetime.now(UTC)
                conn.execute(
                    "INSERT INTO trusted (value, kind, note, added_at) VALUES (?, ?, ?, ?)",
                    (normalized, kind, note, added_at.isoformat()),
                )
        return TrustEntry(normalized, kind, note, added_at)

    def remove(self, value: str) -> bool:
        try:
            normalized, _ = _normalize(value)
        except ValueError:
            return False
        with closing(_connect(self._db_path)) as conn, conn:
            cur = conn.execute("DELETE FROM trusted WHERE value = ?", (normalized,))
            return cur.rowcount > 0

    def list(self) -> list[TrustEntry]:
        with closing(_connect(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT value, kind, note, added_at FROM trusted ORDER BY kind, value"
            ).fetchall()
        return [
            TrustEntry(v, k, n, datetime.fromisoformat(a)) for v, k, n, a in rows
        ]

    def is_trusted(self, address: str) -> bool:
        parts = _split_address(address)
        if parts is None:
            return False
        local, domain = parts
        labels = domain.split(".")
        candidates = [f"{local}@{domain}"] + [
            ".".join(labels[i:]) for i in range(len(labels) - 1)
        ]
        marks = ",".join("?" * len(candidates))
        with closing(_connect(self._db_path)) as conn:
            row = conn.execute(
                f"SELECT 1 FROM trusted WHERE value IN ({marks}) LIMIT 1", candidates
            ).fetchone()
        return row is not None


class StateStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        with closing(_connect(db_path)) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS processed ("
                "provider TEXT NOT NULL, account TEXT NOT NULL, "
                "message_id TEXT NOT NULL, outcome TEXT NOT NULL, "
                "probability REAL, processed_at TEXT NOT NULL, "
                "PRIMARY KEY (provider, account, message_id))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cursors ("
                "provider TEXT NOT NULL, account TEXT NOT NULL, "
                "cursor TEXT NOT NULL, PRIMARY KEY (provider, account))"
            )

    def is_processed(self, provider: str, account: str, message_id: str) -> bool:
        with closing(_connect(self._db_path)) as conn:
            row = conn.execute(
                "SELECT 1 FROM processed WHERE provider = ? AND account = ? "
                "AND message_id = ?",
                (provider, account, message_id),
            ).fetchone()
        return row is not None

    def mark_processed(
        self,
        provider: str,
        account: str,
        message_id: str,
        outcome: str,
        probability: float | None = None,
    ) -> None:
        with closing(_connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO processed "
                "(provider, account, message_id, outcome, probability, processed_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (provider, account, message_id) DO UPDATE SET "
                "outcome = excluded.outcome, probability = excluded.probability, "
                "processed_at = excluded.processed_at",
                (
                    provider,
                    account,
                    message_id,
                    outcome,
                    probability,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def get_cursor(self, provider: str, account: str) -> datetime | None:
        with closing(_connect(self._db_path)) as conn:
            row = conn.execute(
                "SELECT cursor FROM cursors WHERE provider = ? AND account = ?",
                (provider, account),
            ).fetchone()
        return datetime.fromisoformat(row[0]) if row else None

    def set_cursor(self, provider: str, account: str, when: datetime) -> None:
        with closing(_connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO cursors (provider, account, cursor) VALUES (?, ?, ?) "
                "ON CONFLICT (provider, account) DO UPDATE SET cursor = excluded.cursor",
                (provider, account, _to_utc(when).isoformat()),
            )

    def stats(self) -> dict[str, int]:
        with closing(_connect(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT outcome, COUNT(*) FROM processed GROUP BY outcome"
            ).fetchall()
        return {outcome: count for outcome, count in rows}
