#!/usr/bin/env python3
"""CLI entry. Implementation is in blockchecks.cli."""

import sys

from blockchecks.cli.commands.pair import cmd_pair
from blockchecks.cli.commands.tcp import cmd_tcp
from blockchecks.cli.commands.udp import cmd_udp
from blockchecks.cli.parser import main

__all__ = ["main", "cmd_tcp", "cmd_udp", "cmd_pair"]

if __name__ == "__main__":
    sys.exit(main())
