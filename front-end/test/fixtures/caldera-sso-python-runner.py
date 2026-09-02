"""Runs infrastructure/caldera/login_handler.py against the committed SSO vectors.

Driven by front-end/test/caldera-sso.test.js, which spawns:

    python3 caldera-sso-python-runner.py <login_handler.py> <vectors.json>

and compares this script's JSON on stdout against the Node verifier's own
answers, case for case. That comparison is the ONLY thing proving the two
implementations of the token contract agree; there is no Caldera here to run
and no way to discover a drift in production except by an instructor being
locked out.

Deliberately imports the handler BY PATH and imports nothing else beyond the
standard library, because login_handler.py's pure half must stay runnable
without Caldera or aiohttp installed. If this script ever needs a dependency,
that is the signal that the pure/glue split in login_handler.py has been broken.
"""

import importlib.util
import json
import sys


def load_handler(path):
    spec = importlib.util.spec_from_file_location("cc_login_handler", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    handler_path, vectors_path = sys.argv[1], sys.argv[2]
    mod = load_handler(handler_path)
    with open(vectors_path, "r", encoding="utf-8") as fh:
        vectors = json.load(fh)

    results = []
    for case in vectors["cases"]:
        entry = {"name": case["name"]}
        try:
            payload = mod.verify_token(
                case["token"],
                vectors["secret"],
                request_path=case["request_path"],
                now=case["verify_at"],
            )
            entry["got"] = "ok"
            entry["payload"] = payload
        except mod.SsoError as err:
            entry["got"] = err.reason
        except Exception as err:  # a crash is a DIFFERENT failure from a reject
            entry["got"] = "crash:%s" % type(err).__name__
        results.append(entry)

    # Fail-closed on the key itself, asserted on this side too: the Node side
    # throws for the same two conditions and both ends must refuse together.
    secret_checks = {}
    for label, env in (
        ("missing", {}),
        ("short", {"CALDERA_SSO_SECRET": "x" * 31}),
        ("whitespace_padded_ok", {"CALDERA_SSO_SECRET": "\n " + ("x" * 32) + " \r\n"}),
        ("ok", {"CALDERA_SSO_SECRET": "x" * 32}),
    ):
        try:
            mod.load_secret(env)
            secret_checks[label] = "ok"
        except mod.SsoError as err:
            secret_checks[label] = err.reason

    # The path reconstruction Caddy's handle_path forces on us. Compared
    # against the Node expectations so a change to one is caught in the other.
    paths = {
        "stripped_root": mod.reconstruct_request_path("/", public_path="/caldera"),
        "stripped_asset": mod.reconstruct_request_path("/js/app.js", public_path="/caldera"),
        "already_prefixed": mod.reconstruct_request_path("/caldera/js/app.js", public_path="/caldera"),
        "forwarded_uri_used": mod.reconstruct_request_path(
            "/js/app.js", public_path="/caldera", forwarded_uri="/caldera/js/app.js?v=1"
        ),
        "forwarded_uri_ignored_when_foreign": mod.reconstruct_request_path(
            "/js/app.js", public_path="/caldera", forwarded_uri="/evil/js/app.js"
        ),
    }

    # The environment contract with infrastructure/caldera/docker-compose.yml,
    # which is owned by another author. A rename there that is not mirrored here
    # rejects EVERY login with 'path_mismatch', which reads as a broken console
    # rather than as a typo — so both spellings are pinned.
    config = {
        "path_prefix_var": mod.public_path({"CALDERA_SSO_PATH_PREFIX": "/authoring"}),
        "path_var_synonym": mod.public_path({"CALDERA_SSO_PATH": "/authoring"}),
        "path_default": mod.public_path({}),
        "user_default": mod.caldera_user_for("instructor", {}),
        "user_from_env": mod.caldera_user_for("instructor", {"CALDERA_SSO_USER": "cybercore"}),
        "admin_falls_back_to_one_account": mod.caldera_user_for(
            "admin", {"CALDERA_SSO_USER": "cybercore"}
        ),
        # The Dockerfile documents the extension point as "a module exposing
        # load()"; Caldera's own documentation says load_login_handler(). Both
        # must resolve or the container will not start.
        "exports_load_login_handler": callable(getattr(mod, "load_login_handler", None)),
        "exports_load_alias": callable(getattr(mod, "load", None)),
        # The pure half must stay importable with no Caldera and no aiohttp, or
        # everything above this line stops being runnable.
        "importable_without_caldera": mod._CALDERA_AVAILABLE is False,
    }

    json.dump(
        {
            "results": results,
            "secret_checks": secret_checks,
            "paths": paths,
            "config": config,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
