"""
=============================================================================
CYBERCORE SSO LOGIN HANDLER FOR CALDERA  —  the verifying half of the contract
=============================================================================

#############################################################################
# THIS FILE HAS NEVER BEEN EXECUTED AGAINST A REAL CALDERA.                 #
#                                                                           #
# There is no Caldera in this repository and none on any cluster reachable   #
# from where it was written. The PURE LOGIC below (parse, MAC, expiry, role, #
# path) is exercised by front-end/test/caldera-sso.test.js, which runs this  #
# module under python3 against tokens minted by the Node side and against a  #
# committed vector fixture — so the CRYPTOGRAPHY is proved. The FRAMEWORK    #
# GLUE at the bottom (LoginHandlerInterface, session establishment) is       #
# written from Caldera's documented extension point and is NOT proved. Read  #
# the "IF THIS DOES NOT WORK" section before debugging it.                   #
#############################################################################

WHAT THIS IS
-----------------------------------------------------------------------------
CyberCore publishes an "authoring" Caldera — a container with NO agents that
executes nothing — behind Caddy at /caldera. Caddy asks CyberCore
(forward_auth) whether the browser is an instructor or an admin; CyberCore
answers 204 and mints a signed, single-use, 60-second token into the
X-CyberCore-Auth response header; Caddy copies that header onto the proxied
request. This module is what reads it, and what turns a valid token into a
Caldera session so the instructor never types the shared 'red' password.

WHY A SIGNED TOKEN AND NOT A PLAIN HEADER
-----------------------------------------------------------------------------
Caddy advisory GHSA-7r4p-vjf4-gxv4: forward_auth's `copy_headers` does NOT
strip a client-supplied copy of a copied header. If the auth service ever
answers 2xx without setting the header, the CLIENT's value passes through. A
handler that trusted `X-CyberCore-User: <id>` would therefore be an identity
injection primitive reachable by anyone who can load the page.

So this module trusts NOTHING about where the header came from. It trusts one
thing only: that the value carries a valid HMAC-SHA256 under a key the client
does not have. A forged header is not an attack, it is a 401.

THE WIRE FORMAT (must match front-end/src/utils/caldera-sso.js exactly)
-----------------------------------------------------------------------------
    X-CyberCore-Auth: v1.<b64url(payload_json)>.<b64url(hmac_sha256)>

  * b64url is base64url with NO padding.
  * The MAC covers the ASCII string "v1.<b64url(payload_json)>" EXACTLY as it
    arrives on the wire — never the raw JSON and never the decoded bytes. That
    is the JWS rule, and it exists because JSON has no canonical form: key
    order, spacing and Unicode escaping all differ between Node and Python, so
    a verifier that re-serialised before checking would reject tokens its own
    minter produced. This module therefore SLICES the received string and never
    rebuilds it.
  * Payload keys, all required:
        sub   str  CyberCore user id
        role  str  the user's REAL role: "instructor" or "admin"
        path  str  the request path prefix the token is valid for, e.g. /caldera
        exp   int  unix seconds, mint time + 60
        jti   str  128-bit nonce, lowercase hex

VERIFICATION, ALL SIX STEPS, IN ORDER, ALL MANDATORY
-----------------------------------------------------------------------------
    1. the header is present and matches the v1 format
    2. the HMAC recomputes and compares equal IN CONSTANT TIME
    3. exp is in the future
    4. role is instructor or admin
    5. the token's path prefix covers the request
    6. SINGLE USE: the jti is POSTed to CyberCore's redeem endpoint and the
       answer is 200. Anything else — 409 (already spent), 401, 503, a
       timeout — rejects the login.

Step 6 lives in CyberCore because THIS CONTAINER HAS NO STATE. No Redis, no
database, nothing that survives a restart or is shared with a second replica.
A nonce store that a restart empties is not a nonce store. CyberCore has Redis
already, so it answers 200 exactly once per jti and 409 forever after, atomic
via SET NX. That is what makes a captured token useless even inside its
60-second window.

fail closed EVERYWHERE
-----------------------------------------------------------------------------
Missing key, short key, unreachable redeem endpoint, unexpected exception —
every one of them rejects the login. There is no default secret and no
development bypass: a baked-in key is a published key, and this key is the only
thing between a forged header and an adversary authoring console.

AND NOTHING HERE IS EVER LOGGED. Not the token, not the MAC, not the jti, not
the secret, not a truncated prefix of any of them, and not the reason code in a
response body. Failures log a short category and nothing else; the reason
("expired" vs "bad signature") is exactly the oracle an attacker wants.

DEPLOYMENT
-----------------------------------------------------------------------------
Caldera reads the handler's dotted import path from conf/local.yml. The image
copies this file to the top of the application directory, so the path is the
bare module name (see infrastructure/caldera/Dockerfile):

    auth.login.handler.module: cybercore_login_handler

Environment, all read at CALL time so a restart picks up a fix. The names are
the ones infrastructure/caldera's docker-compose service actually sets — that
file is owned by another author, so where a name here looks redundant it is
because BOTH spellings are accepted rather than because one was guessed:

    CALDERA_SSO_SECRET      shared HMAC key, >= 32 bytes. REQUIRED, no default.
    CYBERCORE_REDEEM_URL    default http://app:3000/api/caldera/redeem
    CALDERA_SSO_PATH_PREFIX public path this instance is published at, default
                            /caldera (CALDERA_SSO_PATH is accepted as a
                            synonym). See PATH RECONSTRUCTION below — getting
                            this wrong makes every login fail step 5.
    CALDERA_SSO_USER        the Caldera account an SSO login is attached to,
                            default "cybercore", which is the red-group account
                            conf/local.yml defines. It MUST exist there.
    CALDERA_SSO_ADMIN_USER  optional; used for role == "admin" when set. Unset
                            is the normal case: Caldera groups are roles, not
                            tenancy, so there is one account per group and both
                            CyberCore roles land on the same one.
    CALDERA_SSO_TIMEOUT     redeem deadline in seconds, default 5.

PATH RECONSTRUCTION — THE THING MOST LIKELY TO BE WRONG
-----------------------------------------------------------------------------
Caddy's `handle_path /caldera/*` STRIPS the prefix before proxying, so the
request this process sees is "/" or "/js/app.js", NOT "/caldera/...". A naive
step-5 check against request.path would therefore fail every single time. The
glue re-attaches CALDERA_SSO_PATH before checking (unless the path already
carries it, which is what happens if the deployment moves to a dedicated
hostname with no handle_path). X-Forwarded-Uri is preferred when present
because it is the original, but it is NOT trusted blindly: it is a client-
influenceable header, so it is only ever used to make step 5 STRICTER, never to
satisfy a check the reconstructed path would have failed.

IF THIS DOES NOT WORK — THE THREE THINGS TO CHECK FIRST
-----------------------------------------------------------------------------
  a. load_login_handler(services). Caldera imports the configured module and
     calls this factory. If the running Caldera expects a different symbol or a
     different constructor signature, the server refuses to boot and says so —
     that failure is loud, which is why it is first.
  b. SESSION ESTABLISHMENT. _establish_session() below uses
     aiohttp_security.remember(), which is the primitive Caldera's own auth
     service uses. If a Caldera version wraps that in something with extra
     bookkeeping, the browser will appear to log in and then be logged out on
     the next request. Try auth_svc.handle_successful_login first — the code
     already prefers it when it exists.
  c. STEP 5. See PATH RECONSTRUCTION. Symptom: every login rejected, and the
     log line says "path".

=============================================================================
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import time

LOG = logging.getLogger("cybercore.sso")

# ---------------------------------------------------------------------------
# THE CONTRACT. Every constant here has a twin in
# front-end/src/utils/caldera-sso.js and the two must never drift.
# ---------------------------------------------------------------------------

SSO_HEADER = "X-CyberCore-Auth"
TOKEN_VERSION = "v1"
MIN_SECRET_BYTES = 32
SSO_ROLES = frozenset({"instructor", "admin"})

DEFAULT_REDEEM_URL = "http://app:3000/api/caldera/redeem"
DEFAULT_PUBLIC_PATH = "/caldera"
DEFAULT_REDEEM_TIMEOUT = 5.0

# Canonical unpadded base64url and nothing else. Python's
# urlsafe_b64decode is lenient about padding and (with validate=False) about
# stray characters, which on a SIGNED structure is a malleability seam: several
# distinct wire strings would decode to the same payload bytes. The charset is
# checked with this pattern first and a round-trip comparison finishes the job.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# A jti is 128 bits of lowercase hex. Checked before it is put in a JSON body.
_JTI_RE = re.compile(r"^[0-9a-f]{32}$")

# The exact whitespace stripped from the secret, matching SECRET_TRIM in
# caldera-sso.js. NOT str.strip(): Python's strip() and JavaScript's trim()
# disagree at the edges (JS also eats U+FEFF and U+00A0), and a secret that
# differs by one invisible byte between the two ends fails as a bad signature,
# which looks nothing like its cause.
_SECRET_TRIM = " \t\r\n"


class SsoError(Exception):
    """Base for every rejection. Carries a short category, never material.

    `reason` is for the LOG and for the tests. It must never reach an HTTP
    response body: telling a prober whether their forgery failed on the
    signature or on the clock is half the work of forging one.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SsoConfigError(SsoError):
    """The deployment is misconfigured — missing or short key. Fails closed."""


# ---------------------------------------------------------------------------
# PURE LOGIC
#
# Everything from here to the FRAMEWORK GLUE banner imports nothing from
# Caldera and nothing from aiohttp, so it can be unit-tested with a bare
# `python3 -c "import login_handler"`. front-end/test/caldera-sso.test.js does
# exactly that. Keep it that way: an import of the framework up here would make
# the only automated proof of this file's correctness impossible to run.
# ---------------------------------------------------------------------------


def _trim_secret(raw: str) -> str:
    start, end = 0, len(raw)
    while start < end and raw[start] in _SECRET_TRIM:
        start += 1
    while end > start and raw[end - 1] in _SECRET_TRIM:
        end -= 1
    return raw[start:end]


def load_secret(env=None) -> str:
    """Read CALDERA_SSO_SECRET, or raise. There is no fallback, by design.

    Raises SsoConfigError, which every caller turns into a rejected login. A
    Caldera that cannot verify must not admit anyone: the alternative is a box
    that silently accepts whatever header it is handed.
    """
    source = os.environ if env is None else env
    raw = source.get("CALDERA_SSO_SECRET")
    if not isinstance(raw, str):
        raise SsoConfigError("secret_missing")
    secret = _trim_secret(raw)
    if len(secret.encode("utf-8")) < MIN_SECRET_BYTES:
        # The FLOOR, never the length found: "your key is 12 bytes" is a free
        # search-space hint and this message can reach a log file.
        raise SsoConfigError("secret_too_short")
    return secret


def b64url_decode_strict(value: str) -> bytes:
    """Decode canonical unpadded base64url, or raise SsoError('malformed')."""
    if not isinstance(value, str) or not value or not _B64URL_RE.match(value):
        raise SsoError("malformed")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise SsoError("malformed") from None
    # Round-trip: anything that does not re-encode to exactly itself was not
    # canonical, and on a signed structure non-canonical is not "close enough".
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise SsoError("malformed")
    return raw


def _sign(signing_input: str, secret: str) -> bytes:
    return hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()


def path_matches(token_path: str, request_path: str) -> bool:
    """Step 5. Segment-aware, because startswith() alone is a bypass.

    A plain prefix test would let a token minted for "/caldera" authorise
    "/caldera-admin" — a different mount, a different upstream, the same string
    prefix. Equality, a '/' boundary or a '?' boundary, and nothing else.

    Mirrors pathMatches() in caldera-sso.js line for line, including the
    trailing-slash normalisation that makes "/caldera" and "/caldera/" the same
    claim (Caddy's `redir /caldera /caldera/` makes both shapes real).
    """
    if not isinstance(token_path, str) or not isinstance(request_path, str):
        return False
    if not token_path.startswith("/") or not request_path.startswith("/"):
        return False
    trimmed = token_path.rstrip("/") if len(token_path) > 1 else token_path
    if trimmed in ("", "/"):
        return True
    if request_path == trimmed:
        return True
    return request_path.startswith(trimmed + "/") or request_path.startswith(
        trimmed + "?"
    )


def parse_token(token):
    """Step 1. Split and strictly decode. Returns (signing_input, payload_bytes, mac).

    Nothing here is trusted yet — the payload bytes are returned undecoded on
    purpose, so that the caller cannot accidentally read a claim before the MAC
    has been checked.
    """
    if not isinstance(token, str) or not token:
        raise SsoError("malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise SsoError("malformed")
    version, payload_b64, mac_b64 = parts
    if version != TOKEN_VERSION:
        raise SsoError("bad_version")
    payload_bytes = b64url_decode_strict(payload_b64)
    mac = b64url_decode_strict(mac_b64)
    # SLICED FROM THE INPUT, not rebuilt. See the JWS note in the header.
    signing_input = version + "." + payload_b64
    return signing_input, payload_bytes, mac


def verify_token(token, secret, request_path=None, now=None):
    """Steps 1-5, in order, all mandatory. Returns the payload dict or raises.

    Step 6 (single use) is NOT here: it is a network call with a side effect,
    and a function named `verify` that burns a nonce would be called twice by
    the next person to touch this file, whereupon the second call fails for no
    visible reason. See authorize_request().
    """
    signing_input, payload_bytes, mac = parse_token(token)

    # 2. THE MAC, IN CONSTANT TIME.
    #
    # hmac.compare_digest, NEVER ==. Python's bytes __eq__ short-circuits on
    # the first differing byte, so an attacker who can time this endpoint
    # recovers a valid MAC one byte at a time — a real, published attack, not a
    # theoretical one. compare_digest is the whole reason this line exists in
    # its own paragraph.
    expected = _sign(signing_input, secret)
    if not hmac.compare_digest(mac, expected):
        raise SsoError("bad_signature")

    # Only NOW is it safe to parse. Everything below this line is trusted
    # precisely because the signature covered it.
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SsoError("malformed") from None
    if not isinstance(payload, dict):
        raise SsoError("malformed")

    for key in ("sub", "role", "path", "exp", "jti"):
        if payload.get(key) is None:
            raise SsoError("missing_claim")
    if not isinstance(payload["sub"], str) or not isinstance(payload["role"], str):
        raise SsoError("malformed")
    if not isinstance(payload["path"], str) or not isinstance(payload["jti"], str):
        raise SsoError("malformed")

    # 3. EXPIRY. `isinstance(x, bool)` is excluded explicitly because in Python
    # True is an int, and a payload of {"exp": true} would otherwise read as 1
    # and simply look long expired — harmless today, but it is the kind of type
    # confusion that becomes a bypass when someone later flips a comparison.
    exp = payload["exp"]
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise SsoError("malformed")
    current = time.time() if now is None else now
    if exp <= current:
        raise SsoError("expired")

    # 4. ROLE. The second enforcement of the same rule the CyberCore gate
    # already applied, on the far side of the network, so that a mistake in the
    # minting route cannot on its own let a student in.
    if payload["role"] not in SSO_ROLES:
        raise SsoError("bad_role")

    # 5. PATH.
    if request_path is not None and not path_matches(payload["path"], request_path):
        raise SsoError("path_mismatch")

    if not _JTI_RE.match(payload["jti"]):
        raise SsoError("malformed")

    return payload


def reconstruct_request_path(raw_path, public_path=None, forwarded_uri=None):
    """Rebuild the path the CLIENT asked for, for step 5.

    Caddy's `handle_path /caldera/*` strips the prefix, so `raw_path` is "/" or
    "/js/app.js" and comparing it to a token minted for "/caldera" fails every
    time. This re-attaches the prefix.

    forwarded_uri (X-Forwarded-Uri) is the original and is preferred WHEN IT
    AGREES — but it is a header, which means it is client-influenceable, so it
    is never allowed to rescue a path the reconstruction would have rejected.
    It is used only when it already starts with the public path, i.e. only when
    it can make step 5 stricter or identical, never looser.
    """
    base = (public_path or DEFAULT_PUBLIC_PATH).rstrip("/") or ""
    path = raw_path if isinstance(raw_path, str) and raw_path.startswith("/") else "/"
    # Query strings are not part of the comparison; path_matches tolerates one
    # but there is no reason to feed it one.
    path = path.split("?", 1)[0]

    if isinstance(forwarded_uri, str) and forwarded_uri.startswith(base + "/"):
        return forwarded_uri.split("?", 1)[0]
    if base and (path == base or path.startswith(base + "/")):
        return path
    return (base + path) if base else path


def _redeem_url(env=None):
    source = os.environ if env is None else env
    return source.get("CYBERCORE_REDEEM_URL") or DEFAULT_REDEEM_URL


def _redeem_timeout(env=None):
    source = os.environ if env is None else env
    try:
        value = float(source.get("CALDERA_SSO_TIMEOUT", DEFAULT_REDEEM_TIMEOUT))
    except (TypeError, ValueError):
        return DEFAULT_REDEEM_TIMEOUT
    return value if value > 0 else DEFAULT_REDEEM_TIMEOUT


async def redeem_jti(token, jti, env=None, session_factory=None):
    """Step 6. Burn the nonce server-side, and require exactly 200.

    THE ONLY ACCEPTABLE ANSWER IS 200. 409 means the token was already spent —
    a replay, which is the attack this step exists to defeat. Anything else
    (401, 503, a timeout, a DNS failure) means the burn is UNCONFIRMED, and an
    unconfirmed burn is not a burn: admitting the login would quietly restore
    replayability for as long as the outage lasts.

    The token is sent alongside the jti because CyberCore's endpoint is
    published by Caddy's catch-all and therefore reachable from the internet.
    Requiring the token turns "anyone may burn any nonce" into "only the holder
    of this token may burn this token's nonce" — see the long note on
    createCalderaRedeemRouter in front-end/src/routes/caldera-authoring.js. We
    are holding it anyway; it costs nothing.

    aiohttp is imported HERE and not at module scope so the pure logic above
    stays importable in a bare python3 with no third-party packages, which is
    what makes the cross-language test runnable.
    """
    if not _JTI_RE.match(jti or ""):
        raise SsoError("malformed")

    url = _redeem_url(env)
    timeout = _redeem_timeout(env)
    # A BARE NUMBER IS NOT A PORTABLE aiohttp TIMEOUT. aiohttp coerced
    # `timeout=5.0` into ClientTimeout(total=5.0) for most of the 3.x line and
    # then stopped; on a release that does not, ClientSession.post reads
    # `.total` off a float and raises AttributeError. That is caught by the
    # broad `except` below and becomes SsoError("redeem_unreachable"), so it
    # fails CLOSED — but it fails closed on EVERY login, which presents as "the
    # console rejects everyone" with a one-word log line and no clue that the
    # cause is a keyword argument. ClientTimeout is accepted by every aiohttp
    # that has ever had this parameter, so it is built here and the ambiguity
    # is gone. Caldera pins its own aiohttp in requirements.txt and this image
    # does not choose the version, which is exactly why this must not depend on
    # which one lands.
    #
    # Built inside the same branch that imports aiohttp, and NOT hoisted: the
    # injected-session_factory path (the only path any test can drive) must
    # stay runnable in a bare python3 with no third-party packages, and an
    # aiohttp import at the top of this function would end that.
    request_timeout = timeout
    if session_factory is None:
        import aiohttp  # noqa: PLC0415 - deliberate; see docstring

        request_timeout = aiohttp.ClientTimeout(total=timeout)

        def session_factory():
            return aiohttp.ClientSession()

    try:
        async with session_factory() as session:
            async with session.post(
                url,
                json={"jti": jti},
                headers={SSO_HEADER: token},
                timeout=request_timeout,
            ) as response:
                status = response.status
    except Exception:
        # Deliberately broad, and deliberately silent about the cause. The
        # exception text from aiohttp carries the URL, which carries the
        # internal service name — and the login is rejected either way, so
        # there is nothing to gain by distinguishing.
        raise SsoError("redeem_unreachable") from None

    if status == 200:
        return True
    if status == 409:
        raise SsoError("replayed")
    raise SsoError("redeem_refused")


async def authorize_request(headers, request_path, env=None, session_factory=None):
    """All six steps. Returns the payload, or raises SsoError.

    `headers` is any mapping with a case-insensitive .get (aiohttp's
    CIMultiDict is one); passing a plain dict works in tests as long as the key
    is spelled exactly SSO_HEADER.
    """
    secret = load_secret(env)  # raises SsoConfigError -> caller rejects
    token = headers.get(SSO_HEADER) if headers is not None else None
    if not token:
        raise SsoError("no_token")
    payload = verify_token(token, secret, request_path=request_path)
    await redeem_jti(token, payload["jti"], env=env, session_factory=session_factory)
    return payload


def caldera_user_for(role, env=None):
    """Which Caldera account an SSO login is attached to.

    Caldera has no per-user tenancy — conf/local.yml maps credentials into a
    'red' or 'blue' GROUP, which is a role and not an owner, and every red user
    sees every adversary. So this is not "provision an account", it is "pick
    which existing account to sit in". CyberCore keeps the real attribution:
    launching an adversary writes cybercore_incident_run.launched_by, and this
    token has already proved who that is.

    The default matches the account conf/local.yml defines in the red group. It
    is attached BY NAME and never by password — the entrypoint gives that
    account a random per-start password nobody knows, which is what stops the
    disabled login form from being a second door.
    """
    source = os.environ if env is None else env
    if role == "admin":
        admin_user = source.get("CALDERA_SSO_ADMIN_USER")
        if admin_user:
            return admin_user
    return source.get("CALDERA_SSO_USER") or "cybercore"


def public_path(env=None):
    """The path prefix this instance is published at, for step 5.

    Two spellings because the compose service (owned by another author) sets
    CALDERA_SSO_PATH_PREFIX while the shorter CALDERA_SSO_PATH is the obvious
    thing for an operator to reach for. Accepting both costs one line; a silent
    mismatch here rejects EVERY login with 'path', which reads as a broken
    console rather than as a typo.
    """
    source = os.environ if env is None else env
    return (
        source.get("CALDERA_SSO_PATH_PREFIX")
        or source.get("CALDERA_SSO_PATH")
        or DEFAULT_PUBLIC_PATH
    )


# ---------------------------------------------------------------------------
# FRAMEWORK GLUE
#
# NOT PROVED. Everything below imports Caldera and aiohttp, so it cannot run in
# the cross-language test. It is kept as thin as it can be for exactly that
# reason: every line down here is a line no test covers.
# ---------------------------------------------------------------------------

try:  # pragma: no cover - requires a running Caldera
    from aiohttp import web
    from aiohttp_security import remember
    from app.service.interfaces.i_login_handler import LoginHandlerInterface

    _CALDERA_AVAILABLE = True
except ImportError:  # pragma: no cover - the unit-test path
    # Importable WITHOUT Caldera. This is what lets the pure logic above be
    # tested by front-end/test/caldera-sso.test.js; the alternative is a file
    # whose only proof of correctness is that it starts up in production.
    _CALDERA_AVAILABLE = False
    web = None
    remember = None
    LoginHandlerInterface = object


HANDLER_NAME = "CyberCore SSO Login Handler"


class CyberCoreSsoLoginHandler(LoginHandlerInterface):  # pragma: no cover
    """Turns a valid X-CyberCore-Auth token into a Caldera session.

    LoginHandlerInterface is Caldera's supported extension point: conf/local.yml
    names this module in auth.login.handler.module and Caldera calls
    load_login_handler() below to build one.

    The interface has two methods:

      handle_login          the POST to /enter. There is no CyberCore login
                            form here, so this simply refuses — a password
                            prompt reaching this deployment means something
                            bypassed Caddy, and the answer to that is "no",
                            not "let me check the password too".

      handle_login_redirect what an UNAUTHENTICATED request is answered with.
                            This is where SSO happens, because it is the hook
                            that fires before there is a session. Once a
                            session cookie exists Caldera stops calling it,
                            which is also why the single-use burn happens once
                            per LOGIN and not once per asset — forward_auth
                            mints a token per subrequest, but only the first
                            one reaches here.
    """

    def __init__(self, services):
        super().__init__(services, HANDLER_NAME)

    async def handle_login(self, request, **kwargs):
        raise web.HTTPUnauthorized()

    async def handle_login_redirect(self, request, **kwargs):
        try:
            request_path = reconstruct_request_path(
                request.path,
                public_path=public_path(),
                forwarded_uri=request.headers.get("X-Forwarded-Uri"),
            )
            payload = await authorize_request(request.headers, request_path)
        except SsoError as err:
            # ONE line, ONE word, no token material and no user id. And no
            # detail in the RESPONSE at all: the reason is the oracle.
            LOG.warning("cybercore sso rejected a login (%s)", err.reason)
            raise web.HTTPUnauthorized()
        except Exception:
            LOG.exception("cybercore sso handler failed")
            raise web.HTTPUnauthorized()

        username = caldera_user_for(payload["role"])
        response = web.HTTPFound(request.path_qs)
        await self._establish_session(request, response, username)
        # Raised rather than returned: Caldera's callers treat this hook's
        # return value inconsistently across versions, and a raised
        # HTTPRedirection is honoured by aiohttp regardless.
        raise response

    async def _establish_session(self, request, response, username):
        """Attach a Caldera session to `response`.

        NOT PROVED — read this before debugging a login that appears to succeed
        and then immediately forgets itself. aiohttp_security.remember() is the
        primitive Caldera's own auth service uses, so it is the safe default;
        but if a Caldera version wraps it in extra bookkeeping (group
        assignment, an api token), remember() alone leaves a half-built
        session. auth_svc.handle_successful_login is tried first when it
        exists, precisely so a version that has it does the complete job.
        """
        auth_svc = None
        try:
            auth_svc = self.services.get("auth_svc")
        except Exception:
            auth_svc = None

        hook = getattr(auth_svc, "handle_successful_login", None)
        if callable(hook):
            await hook(request, response, username)
            return
        await remember(request, response, username)


def load_login_handler(services):  # pragma: no cover
    """Caldera's factory hook, as its custom-login-handler documentation names it.

    Caldera imports the module named by auth.login.handler.module and calls this
    to build the handler. If a Caldera version looks for a different symbol the
    server refuses to boot and says which — a loud failure, which is why this is
    the first item in "IF THIS DOES NOT WORK" above.
    """
    return CyberCoreSsoLoginHandler(services)


# ALIAS, on purpose. infrastructure/caldera/Dockerfile — written by the author of
# the image, not of this file — documents the extension point as "a module
# exposing load()". Whether the running Caldera calls load_login_handler() or
# load(), one function answers both, and the cost of being wrong is a container
# that will not start. One line is cheaper than that argument.
load = load_login_handler
