#!/usr/bin/env python3
import sys
from src.core.colors import R, W
from src.core.scanner import ThemperV1


def main():
    if len(sys.argv) != 2:
        print(f"{R}Uso: python -m src.main https://ejemplo.com{W}")
        sys.exit(1)

    themper = ThemperV1()
    exit_code = themper.run(sys.argv[1])
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
