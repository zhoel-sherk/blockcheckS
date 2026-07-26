"""UDP voice checker — STUN binding probe for Discord voice servers.

Sends a STUN binding request and checks for a reply.
No Discord token/bot required. Under 1 second per check.

Usage:
  from checkers.udp_voice import stun_probe
  ok, latency_ms, detail = stun_probe("35.217.31.203", 50004)
"""

import socket
import struct
import time
from typing import Optional


def stun_probe(ip: str, port: int = 50004,
               timeout: float = 3.0) -> tuple[bool, float, str]:
    """Send STUN binding request, return (success, latency_ms, detail).

    If DPI blocks UDP, the packet never reaches the voice server
    and no reply is received.
    """
    tid = b"\x00" * 12
    msg = struct.pack(">HH", 0x0001, 0x0000) + tid
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, port))
        data, addr = sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        return True, elapsed, f"{len(data)}B from {addr[0]}:{addr[1]}"
    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, "timeout"
    except OSError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, str(e)[:100]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
