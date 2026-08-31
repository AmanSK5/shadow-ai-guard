"""A stand-in identity provider, for the demo stack only.

WHY THIS EXISTS. Federated sign-in is the one part of this product that
cannot be tried without an account somewhere else: a real Entra tenant, an
app registration, a client secret. That is a reasonable thing to ask of a
deployment and an unreasonable thing to ask of somebody who cloned the repo
ten minutes ago to see what it does.

WHAT IT IS NOT. It is not a fake button and it does not shortcut the
product. The receiver runs its ordinary code path against this: discovery,
the authorization request with PKCE, the code exchange, and every claim
check afterwards - issuer, audience, nonce, expiry, tenant. What changes is
which host answers, nothing else. So walking the wizard here exercises the
real integration, and a bug in it shows up here rather than in front of
somebody's staff.

WHAT IT IS EMPHATICALLY NOT. A security boundary. It signs nothing, it
believes any secret it is given, and it will happily issue a token for
whoever is picked off a list. The receiver's own justification for not
verifying the token signature rests on TLS to a known host, which plain
HTTP inside a compose network is not. None of that matters for a demo and
all of it matters everywhere else, which is why the receiver refuses to
point at anything but Microsoft unless it is told to in so many words, and
says so in its log on every boot when it has been.

Stdlib only, deliberately: this runs on a bare python image with no build
step and nothing to install.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The tenant and application the demo is configured with. Both have to look
# like GUIDs: the receiver refuses anything else long before it gets here,
# which is the check that catches a typo in a real deployment.
TENANT = os.environ.get("MOCK_TENANT", "11111111-2222-3333-4444-555555555555")
CLIENT_ID = os.environ.get("MOCK_CLIENT_ID",
                           "66666666-7777-8888-9999-000000000000")
# Where this provider is reachable from the BROWSER, which is not where it
# is reachable from the receiver: one goes through the published port, the
# other over the compose network. The issuer has to be the browser-facing
# one, because it is what the discovery document advertises and what the
# receiver then compares the token's iss against.
PUBLIC_URL = os.environ.get("MOCK_PUBLIC_URL", "http://localhost:8092")
PORT = int(os.environ.get("MOCK_PORT", "8092"))

# Who can be signed in as. Names match the demo's own seeded people, so the
# account somebody signs in as is one the rest of the portal already has
# something to say about. The address is what the receiver matches on, so
# these have to be the addresses on the demo's accounts.
PEOPLE = [
    {"oid": "00000000-0000-0000-0000-0000000000a1",
     "name": "Gengar", "email": "gengar@example.com",
     "note": "the owner account the demo sets up"},
    {"oid": "00000000-0000-0000-0000-0000000000a2",
     "name": "Snorlax", "email": "snorlax@example.com",
     "note": "an admin, if you created one"},
    {"oid": "00000000-0000-0000-0000-0000000000a3",
     "name": "Nobody At All", "email": "nobody@example.com",
     "note": "no account here - shows the refusal"},
]

# code -> what /token has to answer with. Single use, and short lived for
# the same reason the real one is.
_CODES: dict[str, dict] = {}
CODE_SECONDS = 300


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sweep():
    now = time.time()
    for k in [k for k, v in _CODES.items() if now - v["at"] > CODE_SECONDS]:
        _CODES.pop(k, None)


def _id_token(person: dict, nonce: str) -> str:
    """An unsigned JWT, shaped like the one Entra returns.

    The signature is the literal string "demo" and the receiver does not
    look at it - see the note in its own source about OpenID Connect Core
    3.1.3.7. Everything it DOES check is real and has to be right here, so
    getting any of these claims wrong produces the same refusal a
    misconfigured tenant would.
    """
    header = {"alg": "none", "typ": "JWT"}
    now = int(time.time())
    claims = {
        "iss": "%s/%s/v2.0" % (PUBLIC_URL, TENANT),
        "aud": CLIENT_ID,
        "sub": person["oid"],
        "oid": person["oid"],
        "tid": TENANT,
        "nonce": nonce,
        "iat": now,
        "exp": now + 600,
        # When the person proved who they are, as distinct from when this
        # token was minted. The receiver checks it against the max_age it
        # asked for, and refuses a token that omits it.
        "auth_time": now,
        "name": person["name"],
        "email": person["email"],
        "preferred_username": person["email"],
    }
    return "%s.%s.demo" % (
        _b64u(json.dumps(header).encode()),
        _b64u(json.dumps(claims).encode()))


PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>Sign in - demo identity provider</title>
<style>
 body{{font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;
  background:#f3f3f3;color:#1b1b1b;margin:0;
  display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:#fff;border:1px solid #e0e0e0;padding:36px 40px;
  width:min(420px,92vw);box-shadow:0 2px 6px rgba(0,0,0,.08)}}
 .ms{{display:flex;gap:9px;align-items:center;font-size:15px;font-weight:600;
  margin:0 0 22px}}
 h1{{font-size:22px;font-weight:600;margin:0 0 4px}}
 p.l{{color:#605e5c;font-size:13.5px;margin:0 0 20px}}
 button{{display:flex;width:100%;gap:12px;align-items:center;text-align:left;
  background:#fff;border:1px solid #d2d0ce;padding:11px 13px;margin:0 0 8px;
  font:inherit;cursor:pointer}}
 button:hover{{background:#f3f2f1;border-color:#0067b8}}
 .av{{width:32px;height:32px;flex:none;border-radius:50%;background:#0067b8;
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:600}}
 .who{{min-width:0}}
 .who b{{display:block;font-weight:600;font-size:14px}}
 .who span{{display:block;color:#605e5c;font-size:12px}}
 .warn{{margin:22px 0 0;padding:10px 12px;background:#fff4ce;
  border:1px solid #f2d98c;font-size:12px;color:#4d3f00}}
</style>
<div class=card>
  <p class=ms>
    <svg width=18 height=18 viewBox="0 0 16 16" aria-hidden=true>
      <rect width=7 height=7 x=0 y=0 fill="#F25022"/>
      <rect width=7 height=7 x=9 y=0 fill="#7FBA00"/>
      <rect width=7 height=7 x=0 y=9 fill="#00A4EF"/>
      <rect width=7 height=7 x=9 y=9 fill="#FFB900"/>
    </svg>Demo identity provider</p>
  <h1>Pick an account</h1>
  <p class=l>Standing in for Microsoft Entra. No password is asked for
    because there is nothing here to prove.</p>
  {buttons}
  <p class=warn><b>This is the demo stack.</b> This provider signs nothing
    and verifies nothing. It exists so the sign-in flow can be walked
    without a real tenant.</p>
</div>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ai-guard-demo-idp"

    def log_message(self, fmt, *args):
        print("[demo-idp] " + fmt % args, flush=True)

    # ------------------------------------------------------------ helpers --
    def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Nothing here should ever be cached, least of all a code.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    # --------------------------------------------------------------- GET --
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)

        # Discovery. The receiver asks for exactly this path, with the
        # tenant in it, and refuses if the three keys below are missing.
        if path == "/%s/v2.0/.well-known/openid-configuration" % TENANT:
            return self._json(200, {
                "issuer": "%s/%s/v2.0" % (PUBLIC_URL, TENANT),
                "authorization_endpoint": "%s/authorize" % PUBLIC_URL,
                # Reached from inside the network, by the receiver, so it is
                # the compose service name rather than the published port.
                "token_endpoint": "%s/token" % os.environ.get(
                    "MOCK_INTERNAL_URL", PUBLIC_URL),
                "response_modes_supported": ["query", "form_post"],
                "response_types_supported": ["code"],
                "scopes_supported": ["openid", "profile", "email"],
                "grant_types_supported": ["authorization_code",
                                          "client_credentials"],
            })

        # An unknown tenant answers the way the real one does, so the
        # wizard's "we could not find that tenant" path is reachable here.
        if path.endswith("/.well-known/openid-configuration"):
            return self._json(400, {"error": "invalid_tenant"})

        if path == "/authorize":
            return self._authorize(query)

        if path == "/healthz":
            return self._json(200, {"ok": True})

        return self._send(404, b"not found")

    def _authorize(self, q):
        """Render the account picker. Everything the receiver sent rides
        through the form so /token can check it."""
        def one(k):
            return (q.get(k) or [""])[0]

        if one("client_id") != CLIENT_ID:
            return self._send(400, b"unknown client_id for this demo provider")
        redirect = one("redirect_uri")
        if not redirect:
            return self._send(400, b"no redirect_uri")

        buttons = []
        for i, p in enumerate(PEOPLE):
            initials = "".join(w[0] for w in p["name"].split()[:2]).upper()
            buttons.append(
                '<form method="POST" action="/authorize">'
                + "".join('<input type=hidden name="%s" value="%s">'
                          % (k, html.escape(one(k), quote=True))
                          for k in ("client_id", "redirect_uri", "state",
                                    "nonce", "code_challenge",
                                    "code_challenge_method", "response_mode"))
                + '<input type=hidden name="who" value="%d">' % i
                + '<button type=submit><span class=av>%s</span>'
                  '<span class=who><b>%s</b><span>%s &middot; %s</span></span>'
                  '</button></form>'
                % (html.escape(initials), html.escape(p["name"]),
                   html.escape(p["email"]), html.escape(p["note"])))
        return self._send(200, PAGE.format(buttons="".join(buttons)).encode())

    # -------------------------------------------------------------- POST --
    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())

        def one(k):
            return (form.get(k) or [""])[0]

        if url.path == "/authorize":
            return self._issue_code(one)
        if url.path == "/token":
            return self._token(one)
        return self._send(404, b"not found")

    def _issue_code(self, one):
        """Somebody picked an account. Mint a code and post it back."""
        try:
            person = PEOPLE[int(one("who"))]
        except (ValueError, IndexError):
            return self._send(400, b"no such account")
        _sweep()
        code = _b64u(secrets.token_bytes(24))
        _CODES[code] = {"at": time.time(), "person": person,
                        "nonce": one("nonce"),
                        "challenge": one("code_challenge"),
                        "redirect": one("redirect_uri")}
        # form_post, because that is the response mode the receiver asks
        # for: the code arrives in a POST body rather than a URL, where it
        # would sit in browser history and every proxy log on the way.
        body = ('<!doctype html><meta charset=utf-8><title>Signing in</title>'
                '<body onload="document.forms[0].submit()">'
                '<form method="POST" action="%s">'
                '<input type=hidden name=code value="%s">'
                '<input type=hidden name=state value="%s">'
                '<noscript><button>Continue</button></noscript>'
                '</form>' % (html.escape(one("redirect_uri"), quote=True),
                             html.escape(code, quote=True),
                             html.escape(one("state"), quote=True)))
        return self._send(200, body.encode())

    def _token(self, one):
        grant = one("grant_type")

        # The wizard's "Verify application" step. The real one proves the
        # id and secret are a pair; here any non-empty pair passes, which
        # is the one place this provider is deliberately more generous
        # than Entra.
        if grant == "client_credentials":
            if one("client_id") != CLIENT_ID or not one("client_secret"):
                return self._json(400, {
                    "error": "invalid_client",
                    "error_description": "this demo provider expects the "
                                         "client id the compose file sets"})
            return self._json(200, {"access_token": "demo-access-token",
                                    "token_type": "Bearer", "expires_in": 3600})

        if grant != "authorization_code":
            return self._json(400, {"error": "unsupported_grant_type"})

        _sweep()
        # Single use: popped, so replaying a code fails here exactly as it
        # would against the real thing.
        rec = _CODES.pop(one("code"), None)
        if rec is None:
            return self._json(400, {
                "error": "invalid_grant",
                "error_description": "that code was already used or expired"})

        # PKCE, checked rather than waved through. This is the part worth
        # having real: if the receiver ever stopped sending a verifier that
        # matches its challenge, the demo would catch it.
        verifier = one("code_verifier")
        expect = _b64u(hashlib.sha256(verifier.encode()).digest())
        if not verifier or expect != rec["challenge"]:
            return self._json(400, {
                "error": "invalid_grant",
                "error_description": "the PKCE verifier did not match the "
                                     "challenge this code was issued for"})
        if one("redirect_uri") != rec["redirect"]:
            return self._json(400, {
                "error": "invalid_grant",
                "error_description": "redirect_uri does not match the one the "
                                     "code was issued to"})

        return self._json(200, {
            "token_type": "Bearer", "expires_in": 600,
            "access_token": "demo-access-token",
            "id_token": _id_token(rec["person"], rec["nonce"])})


if __name__ == "__main__":
    print("[demo-idp] tenant=%s client_id=%s issuer=%s/%s/v2.0"
          % (TENANT, CLIENT_ID, PUBLIC_URL, TENANT), flush=True)
    print("[demo-idp] this provider signs nothing and verifies nothing. "
          "It is for the demo stack.", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
