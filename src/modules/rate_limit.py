import requests
from src.core.colors import item, Y, W, box


def test_rate_limit(session, url, scanner):
    box("Test de Rate Limiting", Y)
    blocked = 0
    item("Enviando 10 requests rápidas...", "info")
    for _ in range(10):
        try:
            r = session.get(url, timeout=2)
            if r.status_code == 429:
                blocked += 1
        except Exception:
            pass

    if blocked == 0:
        item("Sin Rate Limit - Vulnerable a DoS/Fuerza bruta", "err")
        scanner.deduct_score(15, "Sin Rate Limiting")
    elif blocked < 5:
        item(f"Rate Limit débil - Solo {blocked}/10 bloqueadas", "warn")
        scanner.deduct_score(8, "Rate Limit débil")
    else:
        item(f"Rate Limit activo - {blocked}/10 bloqueadas", "ok")
