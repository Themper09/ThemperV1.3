#!/usr/bin/env python3
import sys
from src.core.colors import R, W
from src.core.scanner import ThemperV1


def main():
    themper = ThemperV1()
    url = sys.argv[1] if len(sys.argv) > 1 else None
    exit_code = themper.run(url)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
