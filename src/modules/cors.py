import requests
from src.core.colors import item, Y, W, C, BOLD, box


def check_cors(session, url, scanner):
    box("CORS Killer - Multi-Origin Probe", Y)

    origins = [
        ("null", "null"),
        ("evil.com", "https://evil.com"),
        ("sub.evil.com", "https://sub.evil.com"),
        ("evil-domain", "https://evil-domain"),
        ("evil.com:443", "https://evil.com:443"),
        ("evil.com@", "https://evil.com@"),
        ("evil.com%2f", "https://evil.com%2f"),
        ("data:", "data:"),
    ]

    found = False
    for label, origin in origins:
        try:
            hdrs = {"Origin": origin}
            r = session.get(url, headers=hdrs, timeout=3)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao and acao != "":
                found = True
                if acao == "*" and acac.lower() == "true":
                    item(f"[{label}] CRÍTICO: ACAO:* + ACAC:true", "err")
                    scanner.deduct_score(25, f"CORS killer: {label} -> ACAO:* + ACAC:true")
                elif acao == origin:
                    item(f"[{label}] ACAO refleja origen malicioso", "err")
                    scanner.deduct_score(15, f"CORS killer: {label} refleja origen")
                elif acao == "*":
                    item(f"[{label}] ACAO:* wildcard", "warn")
                    scanner.deduct_score(3, f"CORS killer: {label} -> wildcard")
                elif acao != origin and "*" not in acao:
                    item(f"[{label}] ACAO: {acao} (no coincide)", "info")
        except Exception:
            pass

    # Preflight bypass check
    try:
        hdrs = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
        }
        r = session.options(url, headers=hdrs, timeout=3)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acam = r.headers.get("Access-Control-Allow-Methods", "")
        if acao and acam:
            item(f"Preflight {acam} -> ACAO: {acao}", "warn")
            scanner.deduct_score(5, "CORS preflight permite métodos no estándar")
    except Exception:
        item("No se pudo probar preflight", "warn")

    if not found:
        item("Sin cabeceras CORS - no exploitable", "ok")
    else:
        item(f"{BOLD}Exploración CORS completada{W}", "info")
