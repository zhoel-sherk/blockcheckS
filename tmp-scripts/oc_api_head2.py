#!/usr/bin/env python3
import json
import urllib.request
import sys

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
    print("health", call("GET", "/global/health", timeout=5))
    sess = call(
        "POST",
        "/session",
        {"directory": DIR, "title": "cursor-head"},
        timeout=30,
    )
    print("session", sess["id"], "directory", sess.get("directory"))
    sid = sess["id"]
    prompt = (
        "Run this bash command and reply with its stdout only: "
        "cd /home/zhoel/workspace/blockcheckS && git rev-parse --short HEAD"
    )
    out = call(
        "POST",
        f"/session/{sid}/message",
        {
            "parts": [{"type": "text", "text": prompt}],
            "model": {
                "providerID": "opencode-go",
                "modelID": "deepseek-v4-flash",
            },
        },
        timeout=180,
    )
    info = out.get("info") or {}
    print("finish", info.get("finish"), info.get("providerID"), info.get("modelID"))
    for p in out.get("parts") or []:
        t = p.get("type")
        if t == "text":
            print("TEXT:", p.get("text"))
        elif t and "tool" in t:
            print("TOOL:", t, json.dumps(p)[:400])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("FAIL", type(e).__name__, e, file=sys.stderr)
        sys.exit(1)
