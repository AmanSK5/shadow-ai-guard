"""Managed-mode state: enrollment tokens, devices, audit events.

The first stateful thing in the project, and deliberately the only one: a
single SQLite file. Everything else stays disposable, and with MANAGED_MODE
unset State() is never instantiated and no file is created, so classic
deployments keep the property that losing any component loses nothing.

Fleet credentials are stored as hashes only. The plaintext of an enrollment
token or a device credential exists exactly once, in the response that
minted it, and cannot be recovered from here - a copied database file
cannot impersonate a device or an admin. Integration secrets (a log store
password saved in the portal, in the settings table) are the stated
exception: recoverable by design, because the receiver must present them
outward. SECURITY.md carries the trade.

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
  aigt_...  admin session: what a portal login yields, valid for hours
            rather than until revoked, because it stands in for a person at
            a keyboard, not a machine on a schedule.
  aigs_...  setup code: never stored here at all. Generated in memory at
            boot while no admin account exists, printed to the log, and
            good for exactly one thing - creating the first account.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

ENROLL_PREFIX = "aige_"
DEVICE_PREFIX = "aigd_"
SESSION_PREFIX = "aigt_"
SETUP_PREFIX = "aigs_"

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
CREATE TABLE IF NOT EXISTS admin_users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB NOT NULL UNIQUE,
  user_id    TEXT NOT NULL REFERENCES admin_users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS governance_decisions (
  tool_id    TEXT PRIMARY KEY,
  status     TEXT NOT NULL,
  owner      TEXT NOT NULL DEFAULT '',
  review_due TEXT NOT NULL DEFAULT '',
  reason     TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS registry_entries (
  tool_id    TEXT PRIMARY KEY,
  entry      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidate_devices (
  key        TEXT NOT NULL,
  device     TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (key, device)
);
CREATE TABLE IF NOT EXISTS candidates (
  key          TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  name         TEXT NOT NULL,
  vendor       TEXT NOT NULL DEFAULT '',
  category     TEXT NOT NULL DEFAULT '',
  confidence   TEXT NOT NULL DEFAULT '',
  domains      TEXT NOT NULL DEFAULT '[]',
  devices      INTEGER NOT NULL DEFAULT 0,
  evidence     TEXT NOT NULL DEFAULT '',
  source       TEXT NOT NULL DEFAULT '',
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  dismissed_at TEXT,
  dismissed_by TEXT NOT NULL DEFAULT ''
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


# scrypt from the stdlib, so a password store costs no new dependency. The
# parameters ride inside each stored hash, so raising them later only
# affects passwords set after the change - old rows keep verifying.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 16384, 8, 1


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt,
                       n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return "scrypt$%d$%d$%d$%s$%s" % (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
                                      salt.hex(), h.hex())


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, expect = stored.split("$")
        if algo != "scrypt":
            return False
        h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                           n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(h.hex(), expect)
    except (ValueError, TypeError):
        return False


# Verified against when a login names a username that does not exist, so
# that failure runs the same one scrypt derivation as a wrong password for
# a real user. Computed once: deriving it per attempt would make the
# unknown-username path cost two derivations and stand out on a stopwatch.
_DUMMY_HASH = _hash_password(secrets.token_hex(8))


class EnrollError(Exception):
    """A refused enrollment, carrying the HTTP status it should become."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


class AuthError(Exception):
    """A refused admin-auth operation, carrying its HTTP status."""

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

    # ------------------------------------------------ admin auth (portal) --

    def has_admin(self) -> bool:
        with self._lock:
            row = self._db.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone()
        return row is not None

    def create_admin(self, username: str, password: str) -> dict:
        """The first (and for now only) admin account.

        Refuses once any account exists: creating an account is what the
        one-time setup code authorizes, and after that the door is shut.
        More accounts, when they come, will be minted by an admin from
        inside, not by anyone holding a boot log.
        """
        uid = secrets.token_hex(8)
        with self._lock:
            if self._db.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone():
                raise AuthError(409, "an admin account already exists")
            self._db.execute(
                "INSERT INTO admin_users (id, username, password_hash, created_at)"
                " VALUES (?, ?, ?, ?)",
                (uid, username, _hash_password(password), _now()),
            )
            self._event("admin_created", {"user": uid, "username": username})
            self._db.commit()
        return {"id": uid, "username": username}

    def login(self, username: str, password: str, ttl_hours: int = 24) -> dict:
        """A session token for a correct username and password.

        One failure message for both a wrong username and a wrong password:
        naming which half was wrong tells an attacker which usernames exist.
        The scrypt derivation runs either way, so the two failures cost the
        same time as well as carry the same words.
        """
        now = _now()
        with self._lock:
            row = self._db.execute(
                "SELECT id, password_hash FROM admin_users WHERE username = ?",
                (username,),
            ).fetchone()
            stored = row["password_hash"] if row else _DUMMY_HASH
            if not _verify_password(password, stored) or row is None:
                self._event("login_failed", {"username": username[:64]})
                self._db.commit()
                raise AuthError(401, "bad username or password")

            # Expired sessions have nothing left to say; a login is the
            # natural moment to sweep them out.
            self._db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            token = SESSION_PREFIX + secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc)
                       + timedelta(hours=ttl_hours)).isoformat()
            self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (_hash(token), row["id"], now, expires),
            )
            self._db.execute(
                "UPDATE admin_users SET last_login_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            self._event("login", {"user": row["id"]})
            self._db.commit()
        # The one moment the plaintext exists, same as every credential here.
        return {"token": token, "expires_at": expires, "username": username}

    def session_user(self, token: str) -> dict | None:
        """Who this session belongs to, or None if it is not a live one."""
        with self._lock:
            row = self._db.execute(
                "SELECT s.user_id, s.expires_at, u.username"
                " FROM sessions s JOIN admin_users u ON u.id = s.user_id"
                " WHERE s.token_hash = ? AND s.revoked_at IS NULL"
                " AND s.expires_at > ?",
                (_hash(token), _now()),
            ).fetchone()
        return dict(row) if row else None

    def logout(self, token: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?"
                " AND revoked_at IS NULL",
                (_now(), _hash(token)),
            )
            if cur.rowcount:
                self._event("logout", {})
            self._db.commit()
        return bool(cur.rowcount)

    # ------------------------------------------------ settings (managed) --
    # Deployment configuration the portal edits and the receiver serves to
    # the fleet at runtime. Values are stored as JSON so a key can be a
    # list (corp domains) or a flag without a second schema. Precedence is
    # the caller's business: a row here wins over the matching environment
    # variable, and deleting the row falls back to it - main.py implements
    # that, this just stores.

    def get_setting(self, key: str):
        """The parsed value, or None when no row exists. A stored null is
        not a state this API can create - set_setting(None) deletes - so
        None is unambiguous."""
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value"]) if row else None

    def get_settings(self) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}

    def set_setting(self, key: str, value, by: str = ""):
        """Upsert one setting; value None deletes the row (fall back to
        whatever the deployment's environment says)."""
        with self._lock:
            if value is None:
                cur = self._db.execute(
                    "DELETE FROM settings WHERE key = ?", (key,))
                if cur.rowcount:
                    self._event("setting_cleared", {"key": key, "by": by})
            else:
                self._db.execute(
                    "INSERT INTO settings (key, value, updated_at, updated_by)"
                    " VALUES (?, ?, ?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                    " updated_at = excluded.updated_at,"
                    " updated_by = excluded.updated_by",
                    (key, json.dumps(value), _now(), by),
                )
                # The key and who, never the value: corp domains are not a
                # secret, but the event log's rule is ids only and one
                # exception is how the second one happens.
                self._event("setting_changed", {"key": key, "by": by})
            self._db.commit()

    # -------------------------------------- governance decisions (managed) --
    # What the organisation decided about a tool, editable in the portal.
    # The same record shape the governance file holds, minus exceptions -
    # those stay file-only. The portal merges per tool: a row here wins,
    # the file fills the gaps.

    def list_decisions(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT tool_id, status, owner, review_due, reason,"
                " updated_at, updated_by FROM governance_decisions"
                " ORDER BY tool_id"
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_decision(self, tool_id: str, status: str, owner: str,
                        review_due: str, reason: str, by: str = ""):
        with self._lock:
            self._db.execute(
                "INSERT INTO governance_decisions"
                " (tool_id, status, owner, review_due, reason, updated_at, updated_by)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(tool_id) DO UPDATE SET status = excluded.status,"
                " owner = excluded.owner, review_due = excluded.review_due,"
                " reason = excluded.reason, updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (tool_id, status, owner, review_due, reason, _now(), by),
            )
            self._event("decision_recorded", {"tool": tool_id, "status": status,
                                              "by": by})
            self._db.commit()

    def delete_decision(self, tool_id: str, by: str = "") -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM governance_decisions WHERE tool_id = ?", (tool_id,))
            if cur.rowcount:
                self._event("decision_cleared", {"tool": tool_id, "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    # -------------------------------------- custom registry (managed) --
    # Portal-defined tools, the same shape as a shipped registry entry.
    # Stored as validated JSON (main.py owns validation - schema plus the
    # registry build's own rules) and merged into what /registry and
    # /registry/collector serve, so a tool defined in the portal is a tool
    # the fleet detects on its next check-in.

    def list_registry_entries(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT tool_id, entry, created_at, updated_at, updated_by"
                " FROM registry_entries ORDER BY tool_id"
            ).fetchall()
        return [{"tool_id": r["tool_id"], "entry": json.loads(r["entry"]),
                 "created_at": r["created_at"], "updated_at": r["updated_at"],
                 "updated_by": r["updated_by"]} for r in rows]

    def registry_entry_values(self) -> list[dict]:
        """Just the entries themselves, for the serving merge."""
        with self._lock:
            rows = self._db.execute(
                "SELECT entry FROM registry_entries ORDER BY tool_id"
            ).fetchall()
        return [json.loads(r["entry"]) for r in rows]

    def upsert_registry_entry(self, tool_id: str, entry: dict, by: str = ""):
        now = _now()
        with self._lock:
            self._db.execute(
                "INSERT INTO registry_entries"
                " (tool_id, entry, created_at, updated_at, updated_by)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(tool_id) DO UPDATE SET entry = excluded.entry,"
                " updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (tool_id, json.dumps(entry), now, now, by),
            )
            # The id and who, not the entry: identifiers are not secret,
            # but the event log's rule is ids only and it stays one rule.
            self._event("registry_entry_saved", {"tool": tool_id, "by": by})
            self._db.commit()

    def delete_registry_entry(self, tool_id: str, by: str = "") -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM registry_entries WHERE tool_id = ?", (tool_id,))
            if cur.rowcount:
                self._event("registry_entry_deleted", {"tool": tool_id, "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    # ------------------------------------------------ candidates (managed) --
    # Tools the estate observed that nobody has defined: the discovery
    # service's classified DNS residue, and (in time) raw identifiers the
    # collectors surface. A candidate is a suggestion, never a detection -
    # it enters no registry and no register until a human turns it into a
    # registry entry in the portal, or dismisses it. Dismissal is a stored
    # decision, not a deletion: the same domain resurfacing next run must
    # not reopen a question somebody already answered.

    def list_candidates(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT key, kind, name, vendor, category, confidence,"
                " domains, devices, evidence, source, first_seen, last_seen,"
                " dismissed_at, dismissed_by FROM candidates"
                " ORDER BY last_seen DESC"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["domains"] = json.loads(d["domains"])
            out.append(d)
        return out

    def upsert_candidate(self, key: str, kind: str, name: str, vendor: str,
                         category: str, confidence: str, domains: list,
                         devices: int, evidence: str, source: str):
        """New key inserts; a known key refreshes what a rerun can know
        better (device count, confidence, last_seen) and keeps what it
        cannot (first_seen, and any dismissal)."""
        now = _now()
        with self._lock:
            self._db.execute(
                "INSERT INTO candidates (key, kind, name, vendor, category,"
                " confidence, domains, devices, evidence, source,"
                " first_seen, last_seen)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET"
                " vendor = excluded.vendor, category = excluded.category,"
                " confidence = excluded.confidence, domains = excluded.domains,"
                " devices = excluded.devices, evidence = excluded.evidence,"
                " last_seen = excluded.last_seen",
                (key, kind, name, vendor, category, confidence,
                 json.dumps(domains), devices, evidence, source, now, now),
            )
            self._event("candidate_reported", {"key": key, "source": source})
            self._db.commit()

    def observe_candidate(self, key: str, kind: str, name: str,
                          evidence: str, source: str, device: str = ""):
        """An ingest-time sighting, as opposed to a scanner's whole-picture
        report: insert the candidate if it is new, refresh last_seen if it
        is not, and count the reporting device once. devices becomes the
        count of distinct devices observed - findings arrive one at a time,
        so no single report can state a fleet-wide number, and re-reports
        from the same machine must not inflate one. A dismissed candidate
        keeps accumulating sightings without reopening: the decision stands,
        the record stays honest. One event per candidate lifetime, on first
        insert - per-sighting events would bury the audit log under every
        collector run."""
        now = _now()
        with self._lock:
            fresh = self._db.execute(
                "SELECT 1 FROM candidates WHERE key = ?", (key,)
            ).fetchone() is None
            self._db.execute(
                "INSERT INTO candidates (key, kind, name, evidence, source,"
                " first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET last_seen = excluded.last_seen",
                (key, kind, name, evidence, source, now, now),
            )
            if device:
                self._db.execute(
                    "INSERT INTO candidate_devices (key, device, last_seen)"
                    " VALUES (?, ?, ?)"
                    " ON CONFLICT(key, device) DO UPDATE SET"
                    " last_seen = excluded.last_seen",
                    (key, device, now),
                )
                self._db.execute(
                    "UPDATE candidates SET devices = MAX(devices,"
                    " (SELECT COUNT(*) FROM candidate_devices WHERE key = ?))"
                    " WHERE key = ?",
                    (key, key),
                )
            if fresh:
                self._event("candidate_observed", {"key": key,
                                                   "source": source})
            self._db.commit()

    def dismiss_candidate(self, key: str, by: str = "") -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE candidates SET dismissed_at = ?, dismissed_by = ?"
                " WHERE key = ? AND dismissed_at IS NULL",
                (_now(), by, key),
            )
            if cur.rowcount:
                self._event("candidate_dismissed", {"key": key, "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    def change_password(self, new_password: str, current: str | None = None,
                        keep_session: str | None = None):
        """Set the sole admin's password, optionally proving the current one.

        current=None is the break-glass path, reached only with the API
        credential (the operator who can set the receiver's environment
        already owns the box). Every session except keep_session dies with
        the old password - a stolen session must not outlive the password
        change that was made because of it.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT id, password_hash FROM admin_users LIMIT 1"
            ).fetchone()
            if row is None:
                raise AuthError(409, "no admin account exists")
            if current is not None and not _verify_password(
                current, row["password_hash"]
            ):
                raise AuthError(401, "current password is wrong")
            self._db.execute(
                "UPDATE admin_users SET password_hash = ? WHERE id = ?",
                (_hash_password(new_password), row["id"]),
            )
            keep = _hash(keep_session) if keep_session else b""
            self._db.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ?"
                " AND revoked_at IS NULL AND token_hash != ?",
                (_now(), row["id"], keep),
            )
            self._event("password_changed", {"user": row["id"]})
            self._db.commit()
