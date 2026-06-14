G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
B = '\033[94m'
P = '\033[95m'
C = '\033[96m'
W = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'


def box(title, color=B):
    print(f"\n{color}{BOLD}┌{'─'*66}┐")
    print(f"│ {title:<64} │")
    print(f"└{'─'*66}┘{W}")


def item(text, status="info"):
    icons = {"ok": f"{G}✓{W}", "warn": f"{Y}⚠{W}", "err": f"{R}✗{W}", "info": f"{C}◆{W}"}
    print(f" {icons[status]} {text}")
