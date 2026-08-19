"""UDP voice checker — Discord voice liveness probes.

Two protocols (not interchangeable):
  - RFC 5389 STUN Binding (20B, magic cookie) — response type 0x0101
  - Discord IP Discovery (74B official) — response type 0x0002

No Discord token required for basic liveness. Scapy not used.
"""

import random
import socket
import struct
import time

# Discord IP Discovery (docs): Type(2)+Length(2)+SSRC(4)+Address(64)+Port(2) = 74
IP_DISCOVERY_BODY_LEN = 70
IP_DISCOVERY_TOTAL = 74


def build_ip_discovery_request(ssrc: int = 0) -> bytes:
    """Build official 74-byte Discord IP Discovery request (big-endian)."""
    return (
        struct.pack(">HHI", 0x0001, IP_DISCOVERY_BODY_LEN, ssrc & 0xFFFFFFFF)
        + (b"\x00" * 64)  # address placeholder
        + struct.pack(">H", 0)  # port placeholder
    )


def parse_ip_discovery_response(data: bytes) -> dict | None:
    """Validate IP Discovery response; return mapped fields or None."""
    if len(data) < 8:
        return None
    msg_type, length = struct.unpack(">HH", data[:4])
    if msg_type != 0x0002:
        return None
    # Length field is body size (typically 70); tolerate short/long replies
    if length < 6:
        return None
    ssrc = struct.unpack(">I", data[4:8])[0] if len(data) >= 8 else 0
    mapped_ip = ""
    mapped_port = 0
    if len(data) >= 74:
        addr_raw = data[8:72]
        mapped_ip = addr_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        mapped_port = struct.unpack(">H", data[72:74])[0]
    return {
        "ssrc": ssrc,
        "mapped_ip": mapped_ip,
        "mapped_port": mapped_port,
        "raw_len": len(data),
    }


def stun_probe(ip: str, port: int = 50004, timeout: float = 3.0) -> tuple[bool, float, str]:
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
            resp_tid = data[8:20]
            if msg_type == 0x0101 and magic == 0x2112A442 and resp_tid == tid:
                return True, elapsed, f"{len(data)}B STUN from {addr[0]}:{addr[1]}"
        return False, elapsed, f"invalid STUN response ({len(data)}B)"
    except TimeoutError:
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


def ip_discovery_probe(
    ip: str, port: int = 50004, ssrc: int = 0, timeout: float = 3.0
) -> tuple[bool, float, str]:
    """Send Discord IP Discovery (74B) request; return (ok, ms, detail).

    SSRC from Voice Ready is ideal; 0 is used for liveness when unknown.
    """
    msg = build_ip_discovery_request(ssrc)
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, port))
        data, addr = sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        parsed = parse_ip_discovery_response(data)
        if parsed:
            extra = ""
            if parsed.get("mapped_ip"):
                extra = f" mapped={parsed['mapped_ip']}:{parsed['mapped_port']}"
            return (
                True,
                elapsed,
                f"{parsed['raw_len']}B IP-discovery from {addr[0]}:{addr[1]}{extra}",
            )
        return False, elapsed, f"invalid IP-discovery response ({len(data)}B)"
    except TimeoutError:
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


def voice_burst_probe(
    ip: str,
    port: int = 50004,
    timeout: float = 3.0,
    ssrc: int = 0,
    burst_bytes: int = 17408,
    packet_size: int = 1400,
) -> tuple[bool, float, str]:
    """UDP media-burst probe — simulate a voice stream >16KB.

    The TSPU "voice traffic" heuristic keys on sustained transfer above the
    16KB buffer (dpi-detector's TCP 16-20KB drop). A single STUN/IP-discovery
    probe (20–74B) never triggers it; a burst of media-sized UDP packets
    (default 17408 B total in 1400 B chunks, Opus-like) does.

    Returns (ok, ms, detail). ``ok`` means the endpoint answered (any UDP
    reply — the connection bypassed the DPI); a total timeout/RST means the
    burst was dropped (blocked). Some endpoints only reply to an RTP-shaped
    first packet, so we seed with a fake RTP header + SSRC.
    """
    sock = None
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Fake RTP header (12B) + Opus payload for the first packet, then bulk.
        rtp = struct.pack(">BBHII", 0x80, 0x78, 0, ssrc & 0xFFFFFFFF, 0)
        payload = bytes((i * 7 + 3) & 0xFF for i in range(packet_size))
        sent = 0
        while sent < burst_bytes:
            chunk = payload if sent > 0 else (rtp + payload[12:])
            sock.sendto(chunk, (ip, port))
            sent += len(chunk)
        # Receive loop — wait for any reply while the burst settles.
        data, addr = sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        return (
            True,
            elapsed,
            f"{len(data)}B UDP reply to {burst_bytes}B burst from {addr[0]}:{addr[1]}",
        )
    except TimeoutError:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, f"timeout after {burst_bytes}B burst"
    except OSError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return False, elapsed, str(e)[:100]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def voice_udp_probe(
    ip: str,
    port: int = 50004,
    timeout: float = 3.0,
    ssrc: int = 0,
    try_burst: bool = False,
    burst_bytes: int = 17408,
) -> tuple[bool, float, str, str]:
    """Probe: RFC5389 STUN → Discord IP Discovery → optional UDP media burst.

    Returns (ok, latency_ms, detail, method) where method is
    'rfc5389', 'ip_discovery', 'burst', or ''.

    ``try_burst`` appends the >16KB media burst (voice-traffic heuristic);
    an endpoint that only answers a sustained stream is detected by it.
    """
    ok, ms, detail = stun_probe(ip, port, timeout)
    if ok:
        return True, ms, detail, "rfc5389"
    ok2, ms2, detail2 = ip_discovery_probe(ip, port, ssrc=ssrc, timeout=timeout)
    if ok2:
        return True, ms2, detail2, "ip_discovery"
    if try_burst:
        ok3, ms3, detail3 = voice_burst_probe(
            ip, port, timeout=timeout, ssrc=ssrc, burst_bytes=burst_bytes
        )
        if ok3:
            return True, ms3, detail3, "burst"
        if detail3 != "timeout":
            return False, ms3, detail3, ""
    # Prefer the more informative failure (non-timeout wins)
    if detail2 != "timeout":
        return False, ms2, detail2, ""
    return False, ms, detail, ""
