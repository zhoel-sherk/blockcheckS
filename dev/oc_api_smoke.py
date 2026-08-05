#!/usr/bin/env python3
"""Minimal OpenCode serve client smoke test."""

import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4096"
DIR = "/home/zhoel/workspace/blockcheckS"


def req(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        print("HTTP", e.code, path, raw[:500], file=sys.stderr)
        raise


def main():
    code, health = req("GET", "/global/health")
    print("health", health)

    # create session
    for payload in (
        {"directory": DIR},
        {},
        {"title": "api-smoke"},
    ):
        try:
            code, sess = req("POST", "/session", payload)
            print("session", json.dumps(sess)[:400])
            break
        except Exception as e:
            print("create failed with", payload, e)
    else:
        sys.exit(2)

    sid = sess.get("id") or sess.get("sessionID") or sess.get("session", {}).get("id")
    print("sid", sid)
    if not sid:
        print("full", sess)
        sys.exit(3)

    # send message - try a few endpoint shapes
    msg = {"parts": [{"type": "text", "text": "Say only the word pong. Do not use tools."}]}
    candidates = [
        (
            "POST",
            f"/session/{sid}/message",
            {
                "message": msg,
                "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            },
        ),
        (
            "POST",
            f"/session/{sid}/prompt",
            {
                "parts": [{"type": "text", "text": "Say only: pong"}],
                "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            },
        ),
        ("POST", f"/session/{sid}/message", msg),
    ]
    for method, path, body in candidates:
        try:
            code, out = req(method, path, body)
            print("OK", path, json.dumps(out)[:800] if out else None)
            break
        except Exception as e:
            print("fail", path, type(e).__name__)
    else:
        # dump openapi paths containing session
        try:
            _, doc = req("GET", "/doc")
        except Exception:
            pass
        sys.exit(4)


if __name__ == "__main__":
    main()
