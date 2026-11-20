"""The stdio server, plus the interactive ``doctor`` credential setup."""

import sys

from .server import mcp


def main() -> None:
    if sys.argv[1:2] == ["doctor"]:
        from .doctor import main as doctor_main

        raise SystemExit(doctor_main(sys.argv[2:]))
    if len(sys.argv) != 1:
        raise SystemExit("Use no arguments for the MCP server, or 'doctor' for credential setup.")
    mcp.run()


if __name__ == "__main__":
    main()
