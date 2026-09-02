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
            nothing else. It is still a credential-minting credential - what
            it mints reports - so a revoked serial is refused rather than
            re-minted, and revocation cannot be undone by the token that
            created the device. Long-lived by default (180 days) because it
            sits inside an MDM artifact, where a short TTL means the
            deployment silently breaks for new machines - its safety comes
            from that narrow reach and from instant revocation, not from a
            short life.
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
import re
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
  last_login_at TEXT,
  role          TEXT NOT NULL DEFAULT 'admin'
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
  dismissed_by TEXT NOT NULL DEFAULT '',
  -- "" | "not_attributable". Dismissing says "not a tool"; this says the
  -- name identifies no program at all - a resolver, a service host, a VPN
  -- tunnel that resolves for everything behind it. Different claim, and
  -- unlike a dismissal it has to reach the views that read process names.
  disposition  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS finding_status (
  key    TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  actor  TEXT NOT NULL DEFAULT '',
  at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_map (
  key        TEXT PRIMARY KEY,
  identity   TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
-- One row per SUBSCRIPTION, not per tool. An organisation does not have "a
-- Claude subscription": it has a Teams contract and a handful of Max seats,
-- on different plans, different renewal dates, often different owners. Keying
-- on tool_id alone meant tracking one and being blind to the other, and the
-- spend total was wrong either way without saying so.
--
-- plan_key is the normalised plan - lowercased, punctuation folded to
-- hyphens, empty becoming "default" so a subscription recorded before plans
-- mattered keeps working untouched.
CREATE TABLE IF NOT EXISTS budget_subscriptions (
  tool_id      TEXT NOT NULL,
  plan_key     TEXT NOT NULL DEFAULT 'default',
  vendor       TEXT NOT NULL DEFAULT '',
  plan         TEXT NOT NULL DEFAULT '',
  currency     TEXT NOT NULL DEFAULT '',
  renewal_date TEXT NOT NULL DEFAULT '',
  owner        TEXT NOT NULL DEFAULT '',
  notes        TEXT NOT NULL DEFAULT '',
  seat_tiers   TEXT NOT NULL DEFAULT '[]',
  covers       TEXT NOT NULL DEFAULT '[]',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tool_id, plan_key)
);
CREATE TABLE IF NOT EXISTS budget_members (
  tool_id    TEXT NOT NULL,
  plan_key   TEXT NOT NULL DEFAULT 'default',
  email      TEXT NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  role       TEXT NOT NULL DEFAULT '',
  seat_tier  TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT 'manual',
  usage      TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tool_id, plan_key, email)
);
-- Per subscription too: a Teams contract has an admin API, a handful of
-- individual Max seats does not, and one key cannot stand for both.
CREATE TABLE IF NOT EXISTS budget_connections (
  tool_id          TEXT NOT NULL,
  plan_key         TEXT NOT NULL DEFAULT 'default',
  provider         TEXT NOT NULL,
  api_key          TEXT NOT NULL,
  last_sync_at     TEXT,
  last_sync_ok     INTEGER NOT NULL DEFAULT 0,
  last_sync_detail TEXT NOT NULL DEFAULT '',
  members_synced   INTEGER NOT NULL DEFAULT 0,
  created_at       TEXT NOT NULL,
  updated_by       TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tool_id, plan_key)
);
-- How one person wants the portal to look, and what it has already shown
-- them. Display state, not governance: nothing here changes what a page
-- reports, only how that person sees it, which is why a viewer writes its
-- own rows freely. Deleting the account takes the rows with it.
CREATE TABLE IF NOT EXISTS user_preferences (
  user_id    TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
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
    # Set on a revoked row to let that serial enroll once more. Revocation is
    # otherwise a tombstone: without this, whoever prompted the revoke could
    # undo it with the enrollment token they already hold.
    ("reenroll_allowed_at", "TEXT"),
)

# Accounts predate roles; a database from before the column gets every
# existing account as admin, which is exactly what those accounts were.
_ADMIN_COLUMNS_ADDED = (
    ("role", "TEXT NOT NULL DEFAULT 'admin'"),
    # Where an account meets an identity provider. Nullable because a local
    # account has never needed one and still does not. It is deliberately
    # NOT the login identifier - username stays that, so `admin` remains a
    # usable local account and a misconfigured provider cannot lock anyone
    # out of their own portal.
    #
    # It is also not the join key after the first federated sign-in. The
    # address matches once, to find the account somebody was invited to;
    # the immutable pair below is written at that moment and every sign-in
    # after that matches on it alone. Microsoft's own guidance is explicit:
    # an address "isn't guaranteed to be correct and is mutable over time.
    # Never use it for authorization", because addresses are reassigned -
    # a joiner inheriting a leaver's address would otherwise inherit their
    # account and their role.
    ("email", "TEXT"),
    ("sso_subject", "TEXT"),
    ("sso_tenant", "TEXT"),
    ("sso_bound_at", "TEXT"),
    # The one account that can still sign in with a password when single
    # sign-on is enforced. Set on the account the setup code created, and
    # never offered as a choice: an escape hatch somebody has to remember
    # to nominate is one that is missing on the day it is needed.
    ("break_glass", "INTEGER NOT NULL DEFAULT 0"),
    # When this account was last told it exists. NULL means nobody has been
    # emailed - either there was no mail server when it was created, or the
    # send failed. It is the difference between "we invited them" and "we
    # assume they know", and only one of those is worth reporting.
    ("invited_at", "TEXT"),
)

# A subscription from before licence coverage covers exactly its own tool,
# which is what an empty list means to every reader.
_BUDGET_SUB_COLUMNS_ADDED = (
    ("covers", "TEXT NOT NULL DEFAULT '[]'"),
)

_CANDIDATE_COLUMNS_ADDED = (
    # A decision about the NAME rather than the thing: this identifies no
    # program, so no view should present it as one.
    ("disposition", "TEXT NOT NULL DEFAULT ''"),
)


def plan_key(plan: str) -> str:
    """A plan name reduced to a key: lowercased, runs of anything that is
    not a letter or digit folded to one hyphen.

    Empty becomes "default" so a subscription recorded before plans were part
    of the identity keeps its row and its members without anyone re-entering
    it. "Max 20" and "max-20" are the same subscription; "Team" and
    "Enterprise" are not.
    """
    out = re.sub(r"[^a-z0-9]+", "-", (plan or "").strip().lower()).strip("-")
    return out or "default"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


# Deliberately not RFC 5322. That grammar accepts addresses no identity
# provider will ever issue, and implementing it badly is worse than checking
# the shape that matters: one @, something either side, a dotted domain.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# The RFC's own ceiling, and enough that the cap never fires on a real one.
_EMAIL_MAX = 254


def normalize_email(email: str) -> str:
    """The stored form of an address, or "" for none.

    Lowercased and stripped, because uniqueness has to mean what a person
    means by it: two accounts differing only in capitals are one identity
    to every provider that would map onto them, and storing both would let
    the mapping resolve two ways.
    """
    address = (email or "").strip().lower()
    if not address:
        return ""
    if len(address) > _EMAIL_MAX or not _EMAIL_RE.match(address):
        raise AuthError(422, "that does not look like an email address")
    return address


# What one account may keep. Bounds rather than trust: these rows are the
# one place an authenticated viewer writes freely, and a preference store
# with no ceiling is a blob store with a login.
MAX_PREFERENCE_KEYS = 50
MAX_PREFERENCE_VALUE = 4096
_PREFERENCE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


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
            have = {r["name"]
                    for r in self._db.execute("PRAGMA table_info(admin_users)")}
            for name, decl in _ADMIN_COLUMNS_ADDED:
                if name not in have:
                    self._db.execute(
                        f"ALTER TABLE admin_users ADD COLUMN {name} {decl}")
            # A database from before the owner role has accounts and no
            # owner. The account the setup code created is the earliest
            # one - create_admin refuses once any account exists, so
            # "earliest" identifies it exactly - and it is promoted.
            # Nothing new is recorded to work this out, and a deployment
            # that has since deleted that account promotes whichever admin
            # is now oldest rather than leaving nobody able to appoint one.
            have_any = self._db.execute(
                "SELECT 1 FROM admin_users LIMIT 1").fetchone()
            if have_any:
                has_owner = self._db.execute(
                    "SELECT 1 FROM admin_users WHERE role = 'owner' LIMIT 1"
                ).fetchone()
                if not has_owner:
                    first = self._db.execute(
                        "SELECT id FROM admin_users WHERE role = 'admin'"
                        " ORDER BY created_at, id LIMIT 1").fetchone()
                    if first is not None:
                        self._db.execute(
                            "UPDATE admin_users SET role = 'owner'"
                            " WHERE id = ?", (first["id"],))
                        self._db.execute(
                            "INSERT INTO events (at, kind, detail)"
                            " VALUES (?, ?, ?)",
                            (_now(), "owner_promoted_on_upgrade",
                             json.dumps({"user": first["id"],
                                         "why": "earliest account, no owner"})))
                # Same reasoning for the break-glass flag: the earliest
                # account is the one the setup code created. A deployment
                # that deleted it falls back to the oldest owner, so the
                # flag is never simply absent while accounts exist.
                marked = self._db.execute(
                    "SELECT 1 FROM admin_users WHERE break_glass = 1 LIMIT 1"
                ).fetchone()
                if not marked:
                    bg = self._db.execute(
                        "SELECT id FROM admin_users WHERE role = 'owner'"
                        " ORDER BY created_at, id LIMIT 1").fetchone()
                    if bg is not None:
                        self._db.execute(
                            "UPDATE admin_users SET break_glass = 1"
                            " WHERE id = ?", (bg["id"],))
            # After the ALTER, never in _SCHEMA: on a database that predates
            # the column the index would be built against a column that does
            # not exist yet. Partial, so the many accounts with no address do
            # not all collide on NULL - only a set address has to be unique,
            # because that is what an identity provider would map onto.
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS admin_users_email"
                " ON admin_users (email) WHERE email IS NOT NULL")
            # One federated identity, one account. Partial for the same
            # reason: most accounts have never signed in that way.
            self._db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS admin_users_sso"
                " ON admin_users (sso_tenant, sso_subject)"
                " WHERE sso_subject IS NOT NULL")
            self._migrate_budget_to_plan_keys()
            have = {r["name"] for r in self._db.execute(
                "PRAGMA table_info(candidates)")}
            for name, decl in _CANDIDATE_COLUMNS_ADDED:
                if name not in have:
                    self._db.execute(
                        f"ALTER TABLE candidates ADD COLUMN {name} {decl}")
            have = {r["name"] for r in self._db.execute(
                "PRAGMA table_info(budget_subscriptions)")}
            for name, decl in _BUDGET_SUB_COLUMNS_ADDED:
                if name not in have:
                    self._db.execute(
                        f"ALTER TABLE budget_subscriptions"
                        f" ADD COLUMN {name} {decl}")
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

            # No live row for this serial: either nothing was ever enrolled
            # under it, or every row was revoked. The second case is an
            # operator's explicit decision, and the enrollment token that
            # first created the device is usually still sitting in the same
            # MDM artifact - so re-enrolling here would hand the credential
            # straight back and make the revoke advisory. Refuse, and say
            # what clears it.
            tomb = None
            if prior is None:
                tomb = self._db.execute(
                    "SELECT id, reenroll_allowed_at FROM devices"
                    " WHERE platform = ? AND serial = ? AND revoked_at IS NOT NULL"
                    " ORDER BY revoked_at DESC LIMIT 1",
                    (platform, serial),
                ).fetchone()
                if tomb is not None and tomb["reenroll_allowed_at"] is None:
                    self._event("enroll_refused_revoked", {
                        "device": tomb["id"], "platform": platform, "serial": serial,
                    })
                    self._db.commit()
                    raise EnrollError(
                        409,
                        "this device was revoked; an admin must allow"
                        " re-enrollment before it can enroll again",
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
                if tomb is not None:
                    # The allowance was for this one enrollment. Spend it, so
                    # revoking the new row re-arms the tombstone rather than
                    # leaving the serial permanently open.
                    self._db.execute(
                        "UPDATE devices SET reenroll_allowed_at = NULL WHERE id = ?",
                        (tomb["id"],),
                    )
                    self._event("reenroll_allowance_used", {
                        "device": did, "after": tomb["id"],
                        "platform": platform, "serial": serial,
                    })
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
                " reenrolled_at, enrollments, last_seen, agent_version, revoked_at,"
                " reenroll_allowed_at"
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

    def allow_reenrollment(self, did: str) -> bool:
        """Let a revoked device's serial enroll once more.

        For the reimage and the replacement machine, which are the honest
        reasons a revoked serial comes back. One enrollment, not a standing
        permission: enroll() clears this the moment it is used, so the new
        credential can be revoked with the same finality as the old one.
        """
        with self._lock:
            cur = self._db.execute(
                "UPDATE devices SET reenroll_allowed_at = ?"
                " WHERE id = ? AND revoked_at IS NOT NULL"
                " AND reenroll_allowed_at IS NULL",
                (_now(), did),
            )
            if cur.rowcount:
                self._event("reenroll_allowed", {"device": did})
            self._db.commit()
        return bool(cur.rowcount)

    # ------------------------------------------------ admin auth (portal) --

    def has_admin(self) -> bool:
        with self._lock:
            row = self._db.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone()
        return row is not None

    def create_admin(self, username: str, password: str) -> dict:
        """The first account, and the deployment's owner.

        Refuses once any account exists: creating the first account is what
        the one-time setup code authorizes, and after that the door is
        shut. Further accounts are minted by an admin from inside
        (create_user below), not by anyone holding a boot log.
        """
        uid = secrets.token_hex(8)
        with self._lock:
            if self._db.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone():
                raise AuthError(409, "an admin account already exists")
            self._db.execute(
                "INSERT INTO admin_users"
                " (id, username, password_hash, created_at, role, break_glass)"
                " VALUES (?, ?, ?, ?, 'owner', 1)",
                (uid, username, _hash_password(password), _now()),
            )
            self._event("admin_created", {"user": uid, "username": username})
            self._db.commit()
        return {"id": uid, "username": username}

    def login(self, username: str, password: str, ttl_hours: int = 24,
              log_failure: bool = True) -> dict:
        """A session token for a correct username and password.

        One failure message for both a wrong username and a wrong password:
        naming which half was wrong tells an attacker which usernames exist.
        The scrypt derivation runs either way, so the two failures cost the
        same time as well as carry the same words.

        log_failure=False skips the per-attempt audit row - the caller's
        throttle records one aggregated event instead, so a sustained
        attack cannot write the audit log full.
        """
        now = _now()
        with self._lock:
            row = self._db.execute(
                "SELECT id, password_hash, break_glass FROM admin_users"
                " WHERE username = ?",
                (username,),
            ).fetchone()
            stored = row["password_hash"] if row else _DUMMY_HASH
            if not _verify_password(password, stored) or row is None:
                if log_failure:
                    self._event("login_failed", {"username": username[:64]})
                    self._db.commit()
                raise AuthError(401, "bad username or password")

            # The credential was right; the policy is what refuses. 403 and
            # not 401, because the caller must be able to tell a rejected
            # password (which should count against the throttle) from a
            # correct one that policy turned away (which must not - it is
            # the wrong person's mistake to be punished for).
            if row["break_glass"] != 1 and self._sso_enforced_locked():
                raise AuthError(
                    403, "single sign-on is required for this account; sign "
                         "in with your work email instead")
            if row["break_glass"] == 1 and self._sso_enforced_locked():
                # The one password that still opens the door while
                # enforcement is on. Worth its own line in the trail: it
                # should be a rare event, and a run of them is a story.
                self._event("break_glass_login", {"user": row["id"]})

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

    def record_login_throttled(self, username: str):
        """The one audit row a burst of failures earns once the throttle
        engages, in place of a row per rejected attempt."""
        with self._lock:
            self._event("login_throttled", {"username": username[:64]})
            self._db.commit()

    def session_user(self, token: str) -> dict | None:
        """Who this session belongs to (and as what role), or None if it is
        not a live one."""
        with self._lock:
            row = self._db.execute(
                "SELECT s.user_id, s.expires_at, u.username, u.role"
                " FROM sessions s JOIN admin_users u ON u.id = s.user_id"
                " WHERE s.token_hash = ? AND s.revoked_at IS NULL"
                " AND s.expires_at > ?",
                (_hash(token), _now()),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------- account management --
    # More than one pair of eyes, without more than one level of trust being
    # implicit: an admin runs the platform, a viewer reads it. Viewer exists
    # for the auditor and the exec - people who need the pages and must not
    # be able to change what the pages say. A role changes in place, and the
    # change is one audit event naming both levels: delete-and-recreate left
    # a reader to correlate a removal with a creation and infer what had
    # happened, and it cost the account its password to say something the
    # trail can state outright.

    ROLES = ("owner", "admin", "viewer")

    # What a role outranks. The rule every account action below enforces:
    # you cannot act on an account that outranks you, and you cannot grant
    # a role above your own. Without it, an admin reaches an owner through
    # any of three doors - reset their password and sign in as them, set
    # their email and sign in through the identity provider, or simply
    # change their role - and the tier above admin would exist in name
    # only. Kubernetes RBAC names this escalation prevention; Entra
    # enforces the same shape by refusing a password reset against a
    # higher-privileged role.
    RANK = {"owner": 3, "admin": 2, "viewer": 1}

    def _outranks(self, actor: str, target: str) -> bool:
        return self.RANK.get(actor, 0) > self.RANK.get(target, 0)

    def _may_act_on(self, by_role: str, target_role: str):
        """Raise unless by_role may act on an account holding target_role.

        by_role empty means the API credential, which is the operator's own
        break-glass and is not role-limited.
        """
        if not by_role:
            return
        if self._outranks(target_role, by_role):
            raise AuthError(403, "that account holds a role above yours")

    def _may_grant(self, by_role: str, role: str):
        if not by_role:
            return
        if self._outranks(role, by_role):
            raise AuthError(403, "you cannot grant a role above your own")

    def _guard_break_glass(self, is_break_glass, verb: str):
        """The escape hatch cannot be removed while it is the only way in.

        With single sign-on enforced, this account's password is what
        reopens the door when the identity provider is the thing that is
        down. Deleting or demoting it then is a lockout that looks like
        routine account tidying right up until it matters.
        """
        if is_break_glass == 1 and self._sso_enforced_locked():
            raise AuthError(
                409, "this is the break-glass account and single sign-on is "
                     "enforced, so it cannot be %s. Turn off \"require "
                     "single sign-on\" first." % verb)

    def _guard_last(self, was: str, becomes: str = ""):
        """Refuse to remove the last owner.

        Callers hold the lock. This replaces the old last-admin floor,
        which existed so a deployment could not lock itself out of its own
        account management - an owner does everything an admin does, so a
        deployment with an owner and no admins is not locked out of
        anything. The owner floor is the one that matters and is stricter
        than the admin floor ever was: an admin cannot make an owner, so
        losing the last one cannot be undone from inside at all.
        """
        if was != "owner" or becomes == "owner":
            return
        n = self._db.execute(
            "SELECT COUNT(*) AS n FROM admin_users WHERE role = 'owner'"
        ).fetchone()["n"]
        if n <= 1:
            raise AuthError(409, "cannot remove the last owner")

    # ------------------------------------------------ enforced sign-in --
    # Enforcement means one thing at the door: a correct password is not
    # enough on its own. It is deliberately checked AFTER the password
    # verifies rather than before, so that a wrong password still answers
    # exactly as it did before this existed. Refusing early would let
    # somebody with no credential at all walk a list of usernames and read
    # off which one is the escape hatch.

    def _sso_enforced_locked(self) -> bool:
        """Enforcement, read without taking the lock.

        login() already holds it, and this lock is not reentrant - calling
        the public reader from in there deadlocks the process rather than
        failing a request, which is the worst shape a bug can take here.
        """
        row = self._db.execute(
            "SELECT value FROM settings WHERE key = ?", ("sso_enforce",)
        ).fetchone()
        return bool(row) and json.loads(row["value"]) == "1"

    def sso_enforced(self) -> bool:
        with self._lock:
            return self._sso_enforced_locked()

    def break_glass_username(self) -> str:
        """The account that keeps its password under enforcement, if any."""
        with self._lock:
            row = self._db.execute(
                "SELECT username FROM admin_users WHERE break_glass = 1"
                " LIMIT 1").fetchone()
        return row["username"] if row else ""

    def an_owner_is_bound(self) -> bool:
        """Whether a real federated sign-in has ever completed for an owner.

        The precondition for enforcing it. An address on an account is an
        intention; a binding is the provider having actually answered for
        somebody who can still turn this back off.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM admin_users WHERE role = 'owner'"
                " AND sso_bound_at IS NOT NULL LIMIT 1").fetchone()
        return row is not None

    def mark_invited(self, uid: str) -> bool:
        """Record that this account has been told it exists."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE admin_users SET invited_at = ? WHERE id = ?",
                (_now(), uid))
            self._event("user_invited", {"user": uid})
            self._db.commit()
        return bool(cur.rowcount)

    def uninvited(self) -> list[dict]:
        """Accounts with an address that nobody has ever been told about.

        The retroactive half of invites: a deployment that created accounts
        before it had a mail server should not be left with a permanent gap
        for everybody it onboarded early.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT id, username, email FROM admin_users"
                " WHERE invited_at IS NULL AND email IS NOT NULL"
                " ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def user_by_id(self, uid: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT id, username, email, role FROM admin_users"
                " WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, username, email, role, created_at, last_login_at,"
                " sso_bound_at, break_glass, invited_at FROM admin_users"
                " ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def create_user(self, username: str, password: str, role: str,
                    by: str = "", email: str = "",
                    by_role: str = "") -> dict:
        if role not in self.ROLES:
            raise AuthError(422, "role must be owner, admin or viewer")
        self._may_grant(by_role, role)
        address = normalize_email(email)
        uid = secrets.token_hex(8)
        with self._lock:
            if self._db.execute(
                "SELECT 1 FROM admin_users WHERE username = ?", (username,)
            ).fetchone():
                raise AuthError(409, "that username already exists")
            if address and self._db.execute(
                "SELECT 1 FROM admin_users WHERE email = ?", (address,)
            ).fetchone():
                raise AuthError(409, "that email address is already on "
                                     "another account")
            self._db.execute(
                "INSERT INTO admin_users"
                " (id, username, password_hash, created_at, role, email)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (uid, username, _hash_password(password), _now(), role,
                 address or None),
            )
            # The address is recorded as set or not, never spelled out: the
            # audit trail says who has an identity mapping, and an events
            # table is not the place to accumulate a staff address book.
            self._event("user_created",
                        {"user": uid, "username": username, "role": role,
                         "email_set": bool(address), "by": by})
            self._db.commit()
        return {"id": uid, "username": username, "role": role,
                "email": address}

    def set_user_email(self, uid: str, email: str, by: str = "",
                       by_role: str = "") -> bool:
        """Set or clear the address an identity provider would map onto.

        Separate from account creation because the accounts that need one
        most already exist. An empty address clears the mapping, which is
        the way back from a typo that took the only spelling of somebody's
        name."""
        address = normalize_email(email)
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM admin_users WHERE id = ?", (uid,)
            ).fetchone()
            if row is None:
                return False
            # The address is what a federated sign-in matches on, so
            # setting it on an account above yours is that account's
            # credentials by another route.
            self._may_act_on(by_role, row["role"])
            if address and self._db.execute(
                "SELECT 1 FROM admin_users WHERE email = ? AND id != ?",
                (address, uid),
            ).fetchone():
                raise AuthError(409, "that email address is already on "
                                     "another account")
            self._db.execute("UPDATE admin_users SET email = ? WHERE id = ?",
                             (address or None, uid))
            self._event("user_email_set",
                        {"user": uid, "email_set": bool(address), "by": by})
            self._db.commit()
        return True

    def set_user_role(self, uid: str, role: str, by: str = "",
                      by_role: str = "") -> bool:
        """Move an account between trust levels.

        Enforcement is live: session_user reads the role off the account row
        on every request, so a demotion refuses the next write without
        waiting for a sign-out, and a promotion needs no more than a
        reload. Sessions are deliberately left alone - revoking them would
        sign someone out to achieve what the join already achieved.
        """
        if role not in self.ROLES:
            raise AuthError(422, "role must be owner, admin or viewer")
        self._may_grant(by_role, role)
        with self._lock:
            row = self._db.execute(
                "SELECT role, break_glass FROM admin_users WHERE id = ?",
                (uid,)
            ).fetchone()
            if row is None:
                return False
            was = row["role"]
            # Demoting it is deleting it by another name: the escape hatch
            # exists to turn enforcement back off, and only an owner can.
            if was == "owner" and role != "owner":
                self._guard_break_glass(row["break_glass"], "demoted")
            # Both ends: granting a role you do not hold is escalation, and
            # so is demoting somebody who outranks you out of the way.
            self._may_act_on(by_role, was)
            if was == role:
                # Idempotent, and no event: the trail records changes, and a
                # write that changed nothing is not one.
                return True
            self._guard_last(was, role)
            self._db.execute("UPDATE admin_users SET role = ? WHERE id = ?",
                             (role, uid))
            self._event("user_role_changed",
                        {"user": uid, "from": was, "to": role, "by": by})
            self._db.commit()
        return True

    def delete_user(self, uid: str, by: str = "", by_role: str = "") -> bool:
        """Remove an account and kill its sessions. The last admin cannot be
        deleted: a deployment with accounts and no admin is locked out of
        its own account management, and the API credential that could fix
        it is optional."""
        with self._lock:
            row = self._db.execute(
                "SELECT role, break_glass FROM admin_users WHERE id = ?",
                (uid,)
            ).fetchone()
            if row is None:
                return False
            self._may_act_on(by_role, row["role"])
            self._guard_last(row["role"])
            self._guard_break_glass(row["break_glass"], "deleted")
            # Sessions reference the account (FK), and a deleted account's
            # sessions have nothing left to say - remove rather than revoke.
            self._db.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
            self._db.execute("DELETE FROM admin_users WHERE id = ?", (uid,))
            self._event("user_deleted", {"user": uid, "by": by})
            self._db.commit()
        return True

    def reset_user_password(self, uid: str, new_password: str,
                            by: str = "", by_role: str = "") -> bool:
        """An admin setting someone else's password. Every session that user
        holds dies with the old one - the reset exists because the old
        credential can no longer be trusted, and that distrust extends to
        anything it minted."""
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM admin_users WHERE id = ?", (uid,)
            ).fetchone()
            if row is None:
                return False
            self._may_act_on(by_role, row["role"])
            self._db.execute(
                "UPDATE admin_users SET password_hash = ? WHERE id = ?",
                (_hash_password(new_password), uid))
            self._db.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ?"
                " AND revoked_at IS NULL", (_now(), uid))
            self._event("password_reset", {"user": uid, "by": by})
            self._db.commit()
        return True

    # -------------------------------------------------- federated sign-in --

    def sso_account(self, tenant: str, subject: str, email: str) -> dict | None:
        """The account this federated identity signs in as, or None.

        Two matches, and the order is the whole design. The immutable pair
        first: once an account has been bound, that binding is the only
        thing that signs it in, and nothing about the address can move it.
        The address second, and only for an account not yet bound - it is
        an invitation, spent the first time somebody accepts it.

        Never creates an account. Somebody who can set an address in a
        tenant cannot mint themselves a way in here; every account exists
        because a person decided it should.
        """
        address = (email or "").strip().lower()
        with self._lock:
            row = self._db.execute(
                "SELECT id, username, role FROM admin_users"
                " WHERE sso_tenant = ? AND sso_subject = ?",
                (tenant, subject)).fetchone()
            if row is not None:
                return dict(row) | {"bound": True}
            if not address:
                return None
            row = self._db.execute(
                "SELECT id, username, role FROM admin_users"
                " WHERE email = ? AND sso_subject IS NULL", (address,)
            ).fetchone()
            return dict(row) | {"bound": False} if row else None

    def sso_bind(self, uid: str, tenant: str, subject: str) -> bool:
        """Write the immutable pair onto an account, once.

        Refuses if the account is already bound to a different identity:
        rebinding is how an address change would move somebody else's
        account, which is exactly what binding exists to stop. Clearing a
        binding is deliberate and separate.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT sso_subject, sso_tenant FROM admin_users WHERE id = ?",
                (uid,)).fetchone()
            if row is None:
                return False
            if row["sso_subject"]:
                if (row["sso_subject"], row["sso_tenant"]) != (subject, tenant):
                    raise AuthError(409, "that account is already linked to a "
                                         "different federated identity")
                return True
            self._db.execute(
                "UPDATE admin_users SET sso_subject = ?, sso_tenant = ?,"
                " sso_bound_at = ? WHERE id = ?",
                (subject, tenant, _now(), uid))
            # The subject is a GUID, and recorded: an operator asking "who
            # is this account" needs to be able to answer it.
            self._event("sso_bound", {"user": uid, "tenant": tenant,
                                      "subject": subject})
            self._db.commit()
        return True

    def sso_unbind(self, uid: str, by: str = "", by_role: str = "") -> bool:
        """Cut an account loose from its federated identity.

        The way back from a wrong binding, and the way an account is handed
        to a different person. Subject to the same rank rule as every other
        account action: unbinding an account above yours would let you
        re-bind it to yourself on the next sign-in.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT role, sso_subject FROM admin_users WHERE id = ?",
                (uid,)).fetchone()
            if row is None:
                return False
            self._may_act_on(by_role, row["role"])
            self._db.execute(
                "UPDATE admin_users SET sso_subject = NULL, sso_tenant = NULL,"
                " sso_bound_at = NULL WHERE id = ?", (uid,))
            self._event("sso_unbound", {"user": uid, "by": by})
            self._db.commit()
        return True

    def sso_login(self, uid: str, ttl_hours: int = 24) -> dict:
        """Mint a session for an account the provider has vouched for.

        Deliberately not login(): there is no password to verify, and the
        throttle that guards password guessing has nothing to guard here.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT username, role FROM admin_users WHERE id = ?",
                (uid,)).fetchone()
            if row is None:
                raise AuthError(404, "no account with that id")
            token = SESSION_PREFIX + secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc)
                       + timedelta(hours=ttl_hours)).isoformat()
            self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at,"
                " expires_at) VALUES (?, ?, ?, ?)",
                (_hash(token), uid, _now(), expires))
            self._db.execute(
                "UPDATE admin_users SET last_login_at = ? WHERE id = ?",
                (_now(), uid))
            self._event("sso_login", {"user": uid})
            self._db.commit()
        return {"token": token, "expires_at": expires,
                "username": row["username"], "role": row["role"]}

    # ---------------------------------------------------- preferences --
    # How one person wants the portal laid out, and what it has already
    # walked them through. Every other write in this file is a governance
    # act by an admin; these are display state a viewer owns for itself,
    # so they are role-free and deliberately unaudited - a layout dragged
    # into a new shape is not an event anyone will ever need to review,
    # and logging it would bury the writes that matter.

    def get_preferences(self, user_id: str) -> dict:
        with self._lock:
            rows = self._db.execute(
                "SELECT key, value FROM user_preferences WHERE user_id = ?",
                (user_id,),
            ).fetchall()
        return {r["key"]: r["value"] for r in rows}

    def set_preferences(self, user_id: str, updates: dict) -> dict:
        """Merge these keys into the account's preferences.

        A merge rather than a replace, so a page that owns one key can save
        it without carrying every other page's state and racing them. A
        None value deletes the key, which is how a setting returns to
        whatever the portal's default becomes later - storing a copy of
        today's default would freeze it.
        """
        for key, value in updates.items():
            if not _PREFERENCE_KEY_RE.match(key):
                raise AuthError(422, "preference keys are 1-64 characters of "
                                     "lowercase letters, digits, . _ -")
            if value is None:
                continue
            if not isinstance(value, str):
                raise AuthError(422, f"preference {key} must be a string")
            if len(value) > MAX_PREFERENCE_VALUE:
                raise AuthError(422, f"preference {key} is longer than "
                                     f"{MAX_PREFERENCE_VALUE} characters")
        with self._lock:
            if self._db.execute(
                "SELECT 1 FROM admin_users WHERE id = ?", (user_id,)
            ).fetchone() is None:
                raise AuthError(404, "no account with that id")
            kept = {r["key"] for r in self._db.execute(
                "SELECT key FROM user_preferences WHERE user_id = ?",
                (user_id,))}
            kept.difference_update(k for k, v in updates.items() if v is None)
            kept.update(k for k, v in updates.items() if v is not None)
            if len(kept) > MAX_PREFERENCE_KEYS:
                raise AuthError(422, f"an account keeps at most "
                                     f"{MAX_PREFERENCE_KEYS} preferences")
            now = _now()
            for key, value in updates.items():
                if value is None:
                    self._db.execute(
                        "DELETE FROM user_preferences"
                        " WHERE user_id = ? AND key = ?", (user_id, key))
                else:
                    self._db.execute(
                        "INSERT INTO user_preferences"
                        " (user_id, key, value, updated_at)"
                        " VALUES (?, ?, ?, ?)"
                        " ON CONFLICT (user_id, key) DO UPDATE SET"
                        " value = excluded.value,"
                        " updated_at = excluded.updated_at",
                        (user_id, key, value, now))
            self._db.commit()
            rows = self._db.execute(
                "SELECT key, value FROM user_preferences WHERE user_id = ?",
                (user_id,),
            ).fetchall()
        return {r["key"]: r["value"] for r in rows}

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

    # ------------------------------------------ identity map (managed) --
    # Which person is behind a device key or a local username. The one
    # piece of configuration that still needed kubectl: it lived only as
    # a file the deployment mounted, while the portal generated the
    # proposal for it and could not accept the corrected version back.
    #
    # Personal data, and the most personal this platform holds - names
    # against machines. Stored plainly because the portal must resolve
    # names to render them, replaced wholesale rather than patched
    # (an operator edits the list in a spreadsheet, not row by row), and
    # written by admins only.

    def list_identity_map(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT key, identity, updated_at, updated_by"
                " FROM identity_map ORDER BY key").fetchall()
        return [dict(r) for r in rows]

    def replace_identity_map(self, entries: list[dict], by: str = "") -> int:
        """The whole map, replacing whatever was there. An empty list
        clears it, which is how a deployment falls back to the mounted
        file - the same shape as clearing any other setting."""
        now = _now()
        with self._lock:
            self._db.execute("DELETE FROM identity_map")
            for e in entries:
                self._db.execute(
                    "INSERT INTO identity_map (key, identity, updated_at,"
                    " updated_by) VALUES (?, ?, ?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET"
                    " identity = excluded.identity,"
                    " updated_at = excluded.updated_at,"
                    " updated_by = excluded.updated_by",
                    (e["key"], e["identity"], now, by))
            # Counts, never names: the audit trail's ids-only rule covers
            # people most of all, and this table is nothing but people.
            self._event("identity_map_replaced",
                        {"count": len(entries), "by": by})
            self._db.commit()
        return len(entries)

    # ---------------------------------------------- budget (managed) --
    # What the organisation pays for, per tool: the subscription (plan,
    # renewal, seat tiers with pricing), the list of members that plan
    # covers, and - where a vendor exposes an admin API - the connection
    # that syncs the members automatically. The vendor API key follows the
    # log-store password's documented trade (SECURITY.md): recoverable by
    # design, because the receiver must present it outward to sync, unlike
    # fleet credentials, which are hashes. It is never echoed by any list
    # or GET; sync_connection_key below is its only reader.

    def _migrate_budget_to_plan_keys(self):
        """Rekey the budget tables from tool_id to (tool_id, plan_key).

        SQLite cannot alter a primary key, so each table is rebuilt and its
        rows copied with a plan_key derived from the plan already recorded.
        Runs inside the caller's transaction and only when the old shape is
        found, so a restart on a migrated database does nothing.

        Nothing is dropped: every existing subscription keeps its row, its
        members and its connection, and lands under the plan it already
        named (or "default" if it named none). A deployment that never
        touched the budget has three empty tables and notices nothing.
        """
        cols = {r["name"] for r in
                self._db.execute("PRAGMA table_info(budget_subscriptions)")}
        if not cols or "plan_key" in cols:
            return
        subs = self._db.execute("SELECT * FROM budget_subscriptions").fetchall()
        members = self._db.execute("SELECT * FROM budget_members").fetchall()
        conns = self._db.execute("SELECT * FROM budget_connections").fetchall()
        keyed = {r["tool_id"]: plan_key(r["plan"]) for r in subs}

        for t in ("budget_subscriptions", "budget_members",
                  "budget_connections"):
            self._db.execute(f"ALTER TABLE {t} RENAME TO {t}_old")
        self._db.executescript(_SCHEMA)

        for r in subs:
            d = dict(r)
            d["plan_key"] = keyed[d["tool_id"]]
            names = ", ".join(d)
            self._db.execute(
                f"INSERT INTO budget_subscriptions ({names})"
                f" VALUES ({', '.join('?' * len(d))})", tuple(d.values()))
        for r in members:
            d = dict(r)
            # A member whose subscription has since gone keeps the default
            # key rather than being dropped on the floor.
            d["plan_key"] = keyed.get(d["tool_id"], "default")
            names = ", ".join(d)
            self._db.execute(
                f"INSERT OR REPLACE INTO budget_members ({names})"
                f" VALUES ({', '.join('?' * len(d))})", tuple(d.values()))
        for r in conns:
            d = dict(r)
            d["plan_key"] = keyed.get(d["tool_id"], "default")
            names = ", ".join(d)
            self._db.execute(
                f"INSERT OR REPLACE INTO budget_connections ({names})"
                f" VALUES ({', '.join('?' * len(d))})", tuple(d.values()))

        for t in ("budget_subscriptions", "budget_members",
                  "budget_connections"):
            self._db.execute(f"DROP TABLE {t}_old")
        self._event("budget_rekeyed_by_plan",
                    {"subscriptions": len(subs), "members": len(members),
                     "connections": len(conns)})

    def list_budget(self) -> dict:
        """Everything the budget view shows: subscriptions with their
        members, and each connection's metadata - provider, sync history,
        whether a key is stored - never the key itself."""
        with self._lock:
            subs = self._db.execute(
                "SELECT tool_id, plan_key, vendor, plan, currency,"
                " renewal_date, owner, notes, seat_tiers, covers, created_at,"
                " updated_at, updated_by FROM budget_subscriptions"
                " ORDER BY tool_id, plan_key"
            ).fetchall()
            members = self._db.execute(
                "SELECT tool_id, plan_key, email, name, role, seat_tier,"
                " source, usage, updated_at FROM budget_members"
                " ORDER BY tool_id, plan_key, email"
            ).fetchall()
            conns = self._db.execute(
                "SELECT tool_id, plan_key, provider, last_sync_at,"
                " last_sync_ok, last_sync_detail, members_synced, created_at,"
                " updated_by FROM budget_connections"
                " ORDER BY tool_id, plan_key"
            ).fetchall()
        # Keyed on the subscription, not the tool: two plans on one tool have
        # different members, and folding them together is how a seat gets
        # counted twice.
        by_sub: dict[tuple, list] = {}
        for m in members:
            by_sub.setdefault((m["tool_id"], m["plan_key"]), []).append({
                "email": m["email"], "name": m["name"], "role": m["role"],
                "seat_tier": m["seat_tier"], "source": m["source"],
                "usage": json.loads(m["usage"] or "{}"),
                "updated_at": m["updated_at"],
            })
        return {
            "subscriptions": [dict(
                r, seat_tiers=json.loads(r["seat_tiers"] or "[]"),
                covers=json.loads(r["covers"] or "[]"),
                members=by_sub.get((r["tool_id"], r["plan_key"]), []))
                for r in subs],
            "connections": [{
                "tool_id": c["tool_id"], "plan_key": c["plan_key"],
                "provider": c["provider"],
                "key_set": True, "last_sync_at": c["last_sync_at"],
                "last_sync_ok": bool(c["last_sync_ok"]),
                "last_sync_detail": c["last_sync_detail"],
                "members_synced": c["members_synced"],
                "created_at": c["created_at"], "updated_by": c["updated_by"],
            } for c in conns],
        }

    def upsert_budget_subscription(self, tool_id: str, fields: dict,
                                   by: str = "", key: str = ""):
        """One subscription, identified by tool AND plan.

        `key` names an existing subscription to edit; without it the plan in
        `fields` decides. That distinction is what lets a plan be renamed -
        editing "Team" to "Teams" updates the row rather than silently
        creating a second subscription beside it.
        """
        now = _now()
        pk = key or plan_key(fields.get("plan", ""))
        with self._lock:
            self._db.execute(
                "INSERT INTO budget_subscriptions (tool_id, plan_key, vendor,"
                " plan, currency, renewal_date, owner, notes, seat_tiers,"
                " covers, created_at, updated_at, updated_by)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(tool_id, plan_key) DO UPDATE SET"
                " vendor = excluded.vendor, plan = excluded.plan,"
                " currency = excluded.currency,"
                " renewal_date = excluded.renewal_date,"
                " owner = excluded.owner, notes = excluded.notes,"
                " seat_tiers = excluded.seat_tiers,"
                " covers = excluded.covers,"
                " updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (tool_id, pk, fields.get("vendor", ""),
                 fields.get("plan", ""),
                 fields.get("currency", ""), fields.get("renewal_date", ""),
                 fields.get("owner", ""), fields.get("notes", ""),
                 json.dumps(fields.get("seat_tiers") or []),
                 json.dumps(fields.get("covers") or []), now, now, by),
            )
            # Members and a connection can exist before the subscription
            # does: you can store a vendor key and sync a member list, then
            # write down what the licence is. Those rows landed under
            # "default" because no plan had been named yet. If this is the
            # tool's only subscription, they belong to it - adopt them
            # rather than stranding them under a key nothing references.
            if pk != "default":
                others = self._db.execute(
                    "SELECT COUNT(*) c FROM budget_subscriptions"
                    " WHERE tool_id = ? AND plan_key != ?",
                    (tool_id, pk)).fetchone()["c"]
                if not others:
                    for t in ("budget_members", "budget_connections"):
                        self._db.execute(
                            f"UPDATE OR REPLACE {t} SET plan_key = ?"
                            " WHERE tool_id = ? AND plan_key = 'default'",
                            (pk, tool_id))
            self._event("budget_subscription_saved",
                        {"tool": tool_id, "plan": pk, "by": by})
            self._db.commit()

    def delete_budget_subscription(self, tool_id: str, by: str = "",
                                   key: str = "default") -> bool:
        """One subscription and everything hanging off it: a member list or a
        stored vendor key with no subscription is orphaned data nobody can
        see or manage, which is the worst kind to keep.

        Scoped to the plan. Deleting the Teams contract must not take the
        individual Max seats with it - they are a different subscription that
        happens to be for the same tool.
        """
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM budget_subscriptions"
                " WHERE tool_id = ? AND plan_key = ?", (tool_id, key))
            self._db.execute(
                "DELETE FROM budget_members WHERE tool_id = ? AND plan_key = ?",
                (tool_id, key))
            self._db.execute(
                "DELETE FROM budget_connections"
                " WHERE tool_id = ? AND plan_key = ?", (tool_id, key))
            if cur.rowcount:
                self._event("budget_subscription_deleted",
                            {"tool": tool_id, "plan": key, "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    def replace_budget_members(self, tool_id: str, members: list[dict],
                               source: str, by: str = "",
                               key: str = "default") -> int:
        """Replace the member rows this source owns; other sources' rows
        stay. A CSV re-import replaces the previous import, an API sync
        replaces the previous sync, and neither clobbers a manual entry.
        The event carries counts, never addresses - the audit trail's
        ids-only rule covers people most of all.

        A write enriches, it does not erase what it does not know: an
        incoming empty name, role, seat tier or usage keeps whatever the
        row already holds. The case this exists for is real - the
        Anthropic and Fireflies APIs report no seat tiers, so a sync
        running after an operator assigned tiers by import must not wipe
        the money math it cannot see. An explicit value still overwrites.
        """
        now = _now()
        keep = ("CASE WHEN excluded.{c} = '{empty}' THEN"
                " budget_members.{c} ELSE excluded.{c} END")
        with self._lock:
            self._db.execute(
                "DELETE FROM budget_members"
                " WHERE tool_id = ? AND plan_key = ? AND source = ?",
                (tool_id, key, source))
            for m in members:
                self._db.execute(
                    "INSERT INTO budget_members (tool_id, plan_key, email,"
                    " name, role, seat_tier, source, usage, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(tool_id, plan_key, email) DO UPDATE SET"
                    " name = " + keep.format(c="name", empty="") + ","
                    " role = " + keep.format(c="role", empty="") + ","
                    " seat_tier = " + keep.format(c="seat_tier", empty="") + ","
                    " usage = " + keep.format(c="usage", empty="{}") + ","
                    " source = excluded.source,"
                    " updated_at = excluded.updated_at",
                    (tool_id, key, m["email"], m.get("name", ""),
                     m.get("role", ""), m.get("seat_tier", ""), source,
                     json.dumps(m.get("usage") or {}), now),
                )
            self._event("budget_members_replaced",
                        {"tool": tool_id, "plan": key, "source": source,
                         "count": len(members), "by": by})
            self._db.commit()
        return len(members)

    def set_budget_connection(self, tool_id: str, provider: str,
                              api_key: str, by: str = "",
                              key: str = "default"):
        """Store or replace the vendor connection. A replaced key resets
        the sync history: what the old key last did says nothing about
        what the new one can do."""
        with self._lock:
            self._db.execute(
                "INSERT INTO budget_connections (tool_id, plan_key,"
                " provider, api_key, last_sync_at, last_sync_ok,"
                " last_sync_detail, members_synced, created_at, updated_by)"
                " VALUES (?, ?, ?, ?, NULL, 0, '', 0, ?, ?)"
                " ON CONFLICT(tool_id, plan_key) DO UPDATE SET"
                " provider = excluded.provider, api_key = excluded.api_key,"
                " last_sync_at = NULL, last_sync_ok = 0,"
                " last_sync_detail = '', members_synced = 0,"
                " updated_by = excluded.updated_by",
                (tool_id, key, provider, api_key, _now(), by),
            )
            self._event("budget_connection_saved",
                        {"tool": tool_id, "plan": key,
                         "provider": provider, "by": by})
            self._db.commit()

    def delete_budget_connection(self, tool_id: str, by: str = "",
                                 key: str = "default") -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM budget_connections"
                " WHERE tool_id = ? AND plan_key = ?", (tool_id, key))
            if cur.rowcount:
                self._event("budget_connection_deleted",
                            {"tool": tool_id, "plan": key, "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    def sync_connection_key(self, tool_id: str,
                            key: str = "default") -> tuple[str, str] | None:
        """(provider, api_key) for the sync call, or None. The only reader
        of the key's plaintext; every other query masks it."""
        with self._lock:
            row = self._db.execute(
                "SELECT provider, api_key FROM budget_connections"
                " WHERE tool_id = ? AND plan_key = ?",
                (tool_id, key)).fetchone()
        return (row["provider"], row["api_key"]) if row else None

    def record_budget_sync(self, tool_id: str, ok: bool, detail: str,
                           count: int, by: str = "", key: str = "default"):
        with self._lock:
            self._db.execute(
                "UPDATE budget_connections SET last_sync_at = ?,"
                " last_sync_ok = ?, last_sync_detail = ?, members_synced = ?"
                " WHERE tool_id = ? AND plan_key = ?",
                (_now(), int(ok), detail, count, tool_id, key))
            self._event("budget_sync", {"tool": tool_id, "plan": key,
                                        "ok": ok,
                                        "count": count, "by": by})
            self._db.commit()

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
                " dismissed_at, dismissed_by, disposition FROM candidates"
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
        cannot (first_seen, and any dismissal). Returns whether the key was
        new, so the caller can notify on a discovery exactly once."""
        now = _now()
        with self._lock:
            fresh = self._db.execute(
                "SELECT 1 FROM candidates WHERE key = ?", (key,)
            ).fetchone() is None
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
        return fresh

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
        return fresh

    # ------------------------------------------------- finding lifecycle --
    # A finding the portal derives (a personal account, say) has no row of
    # its own here - it is recomputed from the log store every load. What
    # DOES belong here is the human's answer to it: spoken to, accepted
    # with a reason, or back to open. Keyed on an opaque string the portal
    # composes, so the receiver never needs to understand the finding shape.

    FINDING_STATUSES = ("acknowledged", "accepted")

    def list_finding_statuses(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT key, status, reason, actor, at FROM finding_status"
            ).fetchall()
        return [dict(r) for r in rows]

    def set_finding_status(self, key: str, status: str, reason: str = "",
                           by: str = ""):
        if status not in self.FINDING_STATUSES:
            raise ValueError("status must be one of %s"
                             % ", ".join(self.FINDING_STATUSES))
        with self._lock:
            self._db.execute(
                "INSERT INTO finding_status (key, status, reason, actor, at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET status = excluded.status,"
                " reason = excluded.reason, actor = excluded.actor,"
                " at = excluded.at",
                (key, status, reason, by, _now()),
            )
            self._event("finding_status_set",
                        {"key": key[:200], "status": status, "by": by})
            self._db.commit()

    def clear_finding_status(self, key: str, by: str = "") -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM finding_status WHERE key = ?", (key,))
            if cur.rowcount:
                self._event("finding_status_cleared",
                            {"key": key[:200], "by": by})
            self._db.commit()
        return bool(cur.rowcount)

    # ---------------------------------------------------------- audit -----

    def list_events(self, limit: int = 200) -> list[dict]:
        """The admin activity trail, newest first. Every write above already
        records itself here; this is the read that makes it an audit log
        rather than a diary nobody opens."""
        with self._lock:
            rows = self._db.execute(
                "SELECT rowid, at, kind, detail FROM events"
                " ORDER BY rowid DESC LIMIT ?", (int(limit),)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except (json.JSONDecodeError, TypeError):
                d["detail"] = {}
            out.append(d)
        return out

    def set_candidate_disposition(self, key: str, disposition: str,
                                  by: str = "") -> bool:
        """Record what a name IS, as distinct from dismissing the row.

        Dismissing says "not a tool" and stops the queue asking. This says
        the name identifies no program, which every view reading a process
        name needs to know - so it is stored where they can all read it
        rather than being spent closing one card.
        """
        with self._lock:
            cur = self._db.execute(
                "UPDATE candidates SET disposition = ?, dismissed_at = ?,"
                " dismissed_by = ? WHERE key = ?",
                (disposition, _now(), by, key))
            self._db.commit()
            return cur.rowcount > 0

    def dispositioned_names(self, disposition: str) -> list:
        """Every candidate name carrying this disposition, lowercased."""
        with self._lock:
            rows = self._db.execute(
                "SELECT name FROM candidates WHERE disposition = ?",
                (disposition,)).fetchall()
        return sorted({(r["name"] or "").strip().lower() for r in rows} - {""})

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
                        keep_session: str | None = None,
                        user_id: str | None = None):
        """Set a user's own password, optionally proving the current one.

        user_id names whose - the session's own user in the normal path.
        current=None with no user_id is the break-glass path, reached only
        with the API credential (the operator who can set the receiver's
        environment already owns the box); it targets the oldest owner,
        which is the account the setup code created, falling back to the
        oldest admin if a deployment has removed its owners. Every session except
        keep_session dies with the old password - a stolen session must not
        outlive the password change that was made because of it.
        """
        with self._lock:
            if user_id is not None:
                row = self._db.execute(
                    "SELECT id, password_hash FROM admin_users WHERE id = ?",
                    (user_id,),
                ).fetchone()
            else:
                # The oldest account that can run the platform: the owner
                # the setup code created, or the oldest admin on a
                # deployment whose owners have all been removed. This used
                # to name role = 'admin' outright, which stopped finding
                # anything the moment the setup account became an owner -
                # breaking the one path that exists for being locked out.
                row = self._db.execute(
                    "SELECT id, password_hash FROM admin_users"
                    " WHERE role IN ('owner', 'admin')"
                    " ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END,"
                    " created_at, id LIMIT 1"
                ).fetchone()
            if row is None:
                raise AuthError(409, "no owner or admin account exists")
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
