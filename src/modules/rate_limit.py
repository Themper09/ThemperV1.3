import requests
from src.core.colors import item, Y, W, box


def test_rate_limit(url, scanner):
    box("Test de Rate Limiting", Y)
    blocked = 0
    item("Enviando 20 requests en 2 segundos...", "info")
    for _ in range(20):
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 429:
                blocked += 1
        except Exception:
            pass

    if blocked == 0:
        item("Sin Rate Limit - Vulnerable a DoS/Fuerza bruta", "err")
        scanner.deduct_score(15, "Sin Rate Limiting")
    elif blocked < 10:
        item(f"Rate Limit débil - Solo {blocked}/20 bloqueadas", "warn")
        scanner.deduct_score(8, "Rate Limit débil")
    else:
        item(f"Rate Limit activo - {blocked}/20 bloqueadas", "ok")
