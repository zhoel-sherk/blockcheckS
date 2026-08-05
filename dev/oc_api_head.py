#!/usr/bin/env python3
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:4096"
DIR = "/home/zhoel/workspace/blockcheckS"


def call(method, path, body=None, timeout=180):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else None


def main():
    health = call("GET", "/global/health", timeout=5)
    print("health", health)

    sess = call("POST", "/session", {"directory": DIR, "title": "cursor-control-smoke"})
    sid = sess["id"]
    print("session", sid, "directory", sess.get("directory"))

    out = call(
        "POST",
        f"/session/{sid}/message",
        {
            "parts": [
                {
                    "type": "text",
                    "text": (
                        "In this repo, run exactly: git rev-parse --short HEAD. "
                        "You may use bash. Reply with the hash only."
                    ),
                }
            ],
            "model": {
                "providerID": "opencode-go",
                "modelID": "deepseek-v4-flash",
            },
        },
    )

    info = out.get("info") or {}
    print("finish", info.get("finish"), "model", info.get("providerID"), info.get("modelID"))
    for p in out.get("parts") or []:
        t = p.get("type")
        if t == "text":
            print("TEXT:", p.get("text"))
        elif t in ("tool", "tool-invocation", "tool_use", "tool-call"):
            print("TOOL:", json.dumps(p)[:300])
        elif t == "reasoning":
            print("REASON:", (p.get("text") or "")[:120])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("FAIL", type(e).__name__, e, file=sys.stderr)
        sys.exit(1)
