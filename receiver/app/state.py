"""Managed-mode state: enrollment tokens, devices, audit events.

The first stateful thing in the project, and deliberately the only one: a
single SQLite file. Everything else stays disposable, and with MANAGED_MODE
unset State() is never instantiated and no file is created, so classic
deployments keep the property that losing any component loses nothing.

Only credential hashes are stored. The plaintext of an enrollment token or a
device credential exists exactly once, in the response that minted it, and
cannot be recovered from here - a copied database file is a list of devices,
not a bag of credentials.

Two credential kinds, distinguishable by prefix so the receiver can route a
presented bearer without trying every table, and so a leaked string is
identifiable in a log:

  aige_...  enrollment token: mints device records at /enroll and does
            nothing else. Long-lived by default (180 days) because it sits
            inside an MDM artifact, where a short TTL means the deployment
            silently breaks for new machines - its safety comes from what it
            cannot do and from instant revocation, not from a short life.
  aigd_...  device credential: one machine's bearer for /report and
            /registry, valid until revoked.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

ENROLL_PREFIX = "aige_"
DEVICE_PREFIX = "aigd_"

# A device that authenticated this recently is alive, and a same-serial
# enrollment must not displace it silently: that is the stolen token
# scenario, not the reimaged laptop one. A reimaged machine stops reporting
# the moment its disk is wiped, so the legitimate case sails through after at
# most this long. A stateless scanner that enrolls on every run is bound by
# the same window, which is why a sub-hourly schedule needs a state dir.
SUPERSEDE_QUIET_SECONDS = 3600

# Platforms whose agents keep no state between runs and so enroll on every
# run by design. The active guard above would misfire for them: an hourly
# scanner's previous run is still inside the window when the next starts,
# and a Job retried after its registry fetch is "actively reporting" itself.
# For these a same-serial enrollment always reissues. The guard bought at
# most an hour's delay against a stolen enrollment token anyway; the lever
# for a scanner is revoking the enrollment token it carries.
STATELESS_PLATFORMS = ("scanner",)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id          TEXT PRIMARY KEY,
  token_hash  BLOB NOT NULL UNIQUE,
  note        TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  revoked_at  TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  platform      TEXT NOT NULL,
  serial        TEXT NOT NULL,
  hostname      TEXT NOT NULL DEFAULT '',
  cred_hash     BLOB NOT NULL UNIQUE,
  enrolled_at   TEXT NOT NULL,
  enrolled_with TEXT NOT NULL REFERENCES enrollment_tokens(id),
  last_seen     TEXT,
  agent_version TEXT NOT NULL DEFAULT '',
  revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS devices_serial ON devices (platform, serial);
CREATE TABLE IF NOT EXISTS events (
  at     TEXT NOT NULL,
  kind   TEXT NOT NULL,
  detail TEXT NOT NULL
);
"""

# Columns added after the first release, applied to databases that predate
# them. CREATE TABLE IF NOT EXISTS leaves an existing table alone, so a
# deployment that upgraded keeps its rows and gains the columns here.
_DEVICE_COLUMNS_ADDED = (
    # A same-serial re-enrollment reissues the credential in place, so the
    # row keeps its id; these are the visible trace that it happened (the
    # reimaged laptop, the stateless scanner - or a displaced device).
    ("reenrolled_at", "TEXT"),
    ("enrollments", "INTEGER NOT NULL DEFAULT 1"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


class EnrollError(Exception):
    """A refused enrollment, carrying the HTTP status it should become."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


class State:
    def __init__(self, path: str):
        # In a deployment the directory is the mounted volume; on a laptop
        # it is whatever STATE_DB_PATH points at, which need not exist yet.
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # One connection, one lock. Findings arrive at human scale (a fleet
        # checking in daily), not at scale where SQLite's single writer is a
        # bottleneck; WAL keeps readers unblocked during the rare write.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(_SCHEMA)
            have = {r["name"] for r in self._db.execute("PRAGMA table_info(devices)")}
            for name, decl in _DEVICE_COLUMNS_ADDED:
                if name not in have:
                    self._db.execute(f"ALTER TABLE devices ADD COLUMN {name} {decl}")
            self._db.commit()

    def _event(self, kind: str, detail: dict):
        # Callers hold the lock. Detail carries ids only, never secrets.
        self._db.execute(
            "INSERT INTO events (at, kind, detail) VALUES (?, ?, ?)",
            (_now(), kind, json.dumps(detail)),
        )

    # ------------------------------------------------- enrollment tokens --

    def mint_token(self, note: str, ttl_days: int = 180) -> dict:
        token = ENROLL_PREFIX + secrets.token_urlsafe(32)
        tid = secrets.token_hex(4)
        expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
        with self._lock:
            self._db.execute(
                "INSERT INTO enrollment_tokens (id, token_hash, note, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (tid, _hash(token), note, _now(), expires),
            )
            self._event("token_minted", {"id": tid, "note": note, "expires_at": expires})
            self._db.commit()
        # The one moment the plaintext exists.
        return {"id": tid, "token": token, "expires_at": expires}

    def list_tokens(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, note, created_at, expires_at, revoked_at"
                " FROM enrollment_tokens ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_token(self, tid: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE enrollment_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (_now(), tid),
            )
            if cur.rowcount:
                self._event("token_revoked", {"id": tid})
            self._db.commit()
        return bool(cur.rowcount)

    # ---------------------------------------------------------- devices --

    def enroll(self, token: str, platform: str, serial: str, hostname: str,
               agent_version: str) -> dict:
        now = _now()
        with self._lock:
            row = self._db.execute(
                "SELECT id, expires_at, revoked_at FROM enrollment_tokens WHERE token_hash = ?",
                (_hash(token),),
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                raise EnrollError(401, "bad enrollment token")
            if row["expires_at"] <= now:
                # Named separately from "bad": an expired token in an MDM
                # artifact is an operations task, not an attack, and the
                # collector puts this string in the MDM log.
                raise EnrollError(401, "enrollment token expired")

            prior = self._db.execute(
                "SELECT id, last_seen FROM devices"
                " WHERE platform = ? AND serial = ? AND revoked_at IS NULL",
                (platform, serial),
            ).fetchone()
            if prior is not None and platform not in STATELESS_PLATFORMS:
                quiet_since = (
                    datetime.now(timezone.utc) - timedelta(seconds=SUPERSEDE_QUIET_SECONDS)
                ).isoformat()
                if prior["last_seen"] is not None and prior["last_seen"] > quiet_since:
                    # The device this would displace reported within the
                    # hour. A reimaged machine is silent by definition, so an
                    # active one being superseded is the stolen-token shape:
                    # refuse, record, and require a manual revoke.
                    self._event("supersede_conflict", {
                        "device": prior["id"], "platform": platform, "serial": serial,
                    })
                    self._db.commit()
                    raise EnrollError(
                        409, "a device with this serial is actively reporting; revoke it first"
                    )

            cred = DEVICE_PREFIX + secrets.token_urlsafe(32)
            if prior is not None:
                # Reissue in place: same device, new credential. The old one
                # is dead the instant the hash is replaced, which is the same
                # property revoke-and-insert had, but the device keeps its id
                # across a reimage and a stateless scanner that enrolls on
                # every run does not leave a revoked row behind each time.
                # enrolled_at stays the first enrollment; reenrolled_at and
                # the count are the operator-visible trace, in place of the
                # revoked row that used to sit beside the new one. A
                # *manually* revoked row is not a prior here (revoked_at set),
                # so it stays as history and a fresh row is made instead.
                did = prior["id"]
                self._db.execute(
                    "UPDATE devices SET hostname = ?, cred_hash = ?, reenrolled_at = ?,"
                    " enrollments = enrollments + 1, enrolled_with = ?, agent_version = ?"
                    " WHERE id = ?",
                    (hostname, _hash(cred), now, row["id"], agent_version, did),
                )
                self._event("reenrolled", {"device": did, "platform": platform,
                                           "serial": serial, "with": row["id"]})
            else:
                did = secrets.token_hex(8)
                self._db.execute(
                    "INSERT INTO devices (id, platform, serial, hostname, cred_hash,"
                    " enrolled_at, enrolled_with, agent_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (did, platform, serial, hostname, _hash(cred), now, row["id"],
                     agent_version),
                )
                self._event("enrolled", {"device": did, "platform": platform,
                                         "serial": serial, "with": row["id"]})
            self._db.commit()
        return {"device_id": did, "device_token": cred}

    def device_for(self, token: str) -> dict | None:
        """The non-revoked device this credential belongs to, or None.

        Lookup is by SHA-256 hash: an attacker without the plaintext cannot
        construct the hash, so an indexed equality match is sufficient and no
        constant-time scan is needed.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT id, platform, serial FROM devices"
                " WHERE cred_hash = ? AND revoked_at IS NULL",
                (_hash(token),),
            ).fetchone()
        return dict(row) if row else None

    def touch_device(self, did: str, agent_version: str = ""):
        with self._lock:
            if agent_version:
                self._db.execute(
                    "UPDATE devices SET last_seen = ?, agent_version = ? WHERE id = ?",
                    (_now(), agent_version, did),
                )
            else:
                self._db.execute(
                    "UPDATE devices SET last_seen = ? WHERE id = ?", (_now(), did),
                )
            self._db.commit()

    def list_devices(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, platform, serial, hostname, enrolled_at, enrolled_with,"
                " reenrolled_at, enrollments, last_seen, agent_version, revoked_at"
                " FROM devices ORDER BY enrolled_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_device(self, did: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (_now(), did),
            )
            if cur.rowcount:
                self._event("revoked", {"device": did})
            self._db.commit()
        return bool(cur.rowcount)
