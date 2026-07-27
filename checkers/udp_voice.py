"""UDP voice checker — RFC 5389 STUN binding probe for Discord voice servers.

Sends a correct 20-byte STUN binding request (with magic cookie 0x2112A442)
and checks for a reply. No Discord token/bot required. Under 1 second per check.
"""

import random
import socket
import struct
import time
from typing import Optional


def stun_probe(ip: str, port: int = 50004,
               timeout: float = 3.0) -> tuple[bool, float, str]:
    """Send RFC 5389 STUN binding request, return (success, latency_ms, detail).

    If DPI blocks UDP, the packet never reaches the voice server
    and no reply is received.

    Correct format: type(2) + length(2) + magic_cookie(4) + txn_id(12) = 20 bytes.
    """
    tid = bytes(random.randint(0, 255) for _ in range(12))
    msg = struct.pack(">HHI", 0x0001, 0x0000, 0x2112A442) + tid
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, port))
        data, addr = sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        # Validate RFC 5389 Binding Success response
        if len(data) >= 20:
            msg_type = struct.unpack(">H", data[:2])[0]
            magic = struct.unpack(">I", data[4:8])[0]
            if msg_type == 0x0101 and magic == 0x2112A442:
                return True, elapsed, f"{len(data)}B STUN from {addr[0]}:{addr[1]}"
        return False, elapsed, f"invalid STUN response ({len(data)}B)"
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
