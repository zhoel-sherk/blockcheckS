#!/usr/bin/env python3
"""blockcheckS — lightspeed DPI strategy tester.

Usage:
  sudo python3 bs.py tcp -d discord.com -s "hostfakesplit:tcp_md5:tcp_ts_up"
  sudo python3 bs.py tcp -d discord.com -c configs/simple_fake_alt2.conf
  sudo python3 bs.py tcp -d discord.com -C configs/          # all configs
  sudo python3 bs.py tcp -d discord.com --test custom --protocol tls12
"""

import argparse
import sys

from engine.strategy_loader import StrategyLoader
from engine.test_runner import TestRunner


def cmd_tcp(args):
    """Test TCP TLS strategies."""
    loader = StrategyLoader()
    mode = None

    if args.config:
        strategies = loader.from_config(args.config)
        mode = "config"
    elif args.configs_dir:
        strategies = loader.from_config_dir(args.configs_dir)
        mode = "configs"
    elif args.file:
        strategies = loader.from_file(args.file)
        mode = "string"
    elif args.strategy:
        strategies = loader.from_string(args.strategy)
        mode = "string"
    elif args.test == "custom":
        strategies = loader.from_custom_dir(args.test_dir, args.protocol)
        mode = "string"
    else:
        print("ERROR: specify --strategy, --config, --configs-dir, --file, or --test")
        return 1

    if not strategies:
        print("ERROR: no strategies loaded")
        return 1

    print(f"\n  blockcheckS — TCP TLS test")
    print(f"  Domain:     {args.domain}")
    print(f"  Mode:       {mode}")
    print(f"  Items:      {len(strategies)}")
    print(f"  Timeout:    {args.timeout}s")
    print()

    runner = TestRunner(ns_name=args.ns)

    if mode == "configs" and strategies:
        report = runner.test_sequential_configs(
            strategies, args.domain,
            timeout=args.timeout,
            qnum=args.qnum,
        )
    elif mode == "config" and strategies:
        report = runner.test_sequential_configs(
            strategies, args.domain,
            timeout=args.timeout,
            qnum=args.qnum,
        )
    else:
        report = runner.test_sequential(
            strategies, args.domain,
            timeout=args.timeout,
            hostlist=[args.domain] if not args.no_hostlist else None,
            qnum=args.qnum,
        )

    print(f"\n  Results: {report.passed}/{len(report.results)} passed "
          f"({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="blockcheckS — lightspeed DPI strategy tester"
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # tcp command
    tcp = sub.add_parser("tcp", help="Test TCP TLS strategies")
    tcp.add_argument("-d", "--domain", required=True,
                     help="Domain to test (e.g., 'discord.com')")
    tcp.add_argument("-s", "--strategy",
                     help="Single strategy string (e.g. 'fake:repeats=6:tcp_ts=-1000')")
    tcp.add_argument("-c", "--config",
                     help="Path to nfqws2 .conf file")
    tcp.add_argument("-C", "--configs-dir",
                     help="Directory with .conf files (test all)")
    tcp.add_argument("-f", "--file",
                     help="File with strategies (one per line)")
    tcp.add_argument("--test", choices=["custom", "standard"],
                     help="Use built-in test suites")
    tcp.add_argument("--test-dir", default="/opt/zapret2/blockcheck2.d",
                     help="blockcheck2.d directory for custom tests")
    tcp.add_argument("--protocol", default="tls12",
                     choices=["http", "tls12", "tls13", "quic", "udp_voice"],
                     help="Protocol for custom test")
    tcp.add_argument("--timeout", type=float, default=5.0,
                     help="Curl timeout in seconds (default: 5)")
    tcp.add_argument("--no-hostlist", action="store_true",
                     help="Process ALL TCP 443 (no hostlist filter)")
    tcp.add_argument("--qnum", type=int, default=200,
                     help="NFQUEUE number (default: 200)")
    tcp.add_argument("--ns",
                     help="Run inside network namespace")

    # scan command (placeholder for Phase 2)
    scan = sub.add_parser("scan", help="Full scan (Phase 2)")
    scan.add_argument("-d", "--domain", required=True)
    scan.add_argument("-f", "--file")
    scan.add_argument("--test", choices=["custom", "standard"], default="custom")
    scan.add_argument("--test-dir", default="/opt/zapret2/blockcheck2.d")
    scan.add_argument("--protocol", default="tls12")
    scan.add_argument("--timeout", type=float, default=3.0)
    scan.add_argument("--qnum", type=int, default=200)
    scan.add_argument("--ns")

    # udp command (placeholder for Phase 3)
    udp = sub.add_parser("udp", help="Test UDP voice strategies (Phase 3)")
    udp.add_argument("-d", "--domain")
    udp.add_argument("-s", "--strategy")
    udp.add_argument("--ip", default="35.217.31.203")
    udp.add_argument("--port", type=int, default=50004)

    args = parser.parse_args()

    if args.command == "tcp":
        return cmd_tcp(args)
    elif args.command == "scan":
        return cmd_tcp(args)  # redirect to tcp for now
    elif args.command == "udp":
        print("UDP testing coming in Phase 3")
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
