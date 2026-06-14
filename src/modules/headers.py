import requests
from src.core.colors import item, C, G, R, Y, BOLD, DIM, W, box


def check_security_headers(headers, html, url, scanner):
    box("ANÁLISIS DE VULNERABILIDADES", R)

    print(f"\n{C}{BOLD}TODOS LOS HEADERS HTTP{W}")
    for k, v in headers.items():
        print(f"{DIM}{k}: {v}{W}")

    print(f"\n{C}{BOLD}Tabla de Cabeceras de Seguridad{W}")
    print(f"{DIM}{'Cabecera':<30} {'Estado':<15} {'Impacto'}{W}")
    print(f"{DIM}{'─'*65}{W}")

    sec_headers = {
        'X-Frame-Options': ['Clickjacking', 10],
        'X-Content-Type-Options': ['MIME Sniffing', 5],
        'Strict-Transport-Security': ['SSL Stripping', 10],
        'Content-Security-Policy': ['XSS/Inyección', 20],
        'Referrer-Policy': ['Fuga de Referrer', 5],
        'Permissions-Policy': ['Abuso de APIs', 5]
    }

    for h, (vuln, points) in sec_headers.items():
        if h not in headers:
            print(f"{R}{h:<30} {'FALTANTE':<15} {vuln}{W}")
            scanner.deduct_score(points, f"Falta {h}")
        else:
            val = headers[h][:40] + "..." if len(headers[h]) > 40 else headers[h]
            print(f"{G}{h:<30} {'PRESENTE':<15} {C}{val}{W}")

    print(f"\n{C}{BOLD}Cookies y Fuga de Info{W}")
    if 'Set-Cookie' in headers:
        c = headers['Set-Cookie']
        item(f"Cookie detectada: {C}{c[:60]}...{W}", "info")
        if 'HttpOnly' not in c:
            item("Cookie sin HttpOnly", "err")
            scanner.deduct_score(10, "Cookie sin HttpOnly")
        if 'Secure' not in c:
            item("Cookie sin Secure", "err")
            scanner.deduct_score(10, "Cookie sin Secure")
        if 'SameSite' not in c:
            item("Cookie sin SameSite", "warn")
            scanner.deduct_score(5, "Cookie sin SameSite")
    else:
        item("No se detectaron cookies", "ok")

    if 'X-Powered-By' in headers:
        item(f"X-Powered-By expone: {R}{headers['X-Powered-By']}{W}", "warn")
        scanner.deduct_score(3, "Fuga de info X-Powered-By")

    print(f"\n{C}{BOLD}Test XSS Básico{W}")
    try:
        payload = "<script>alert('themper')</script>"
        r = requests.get(f"{url}?themper={payload}", timeout=5)
        if payload in r.text:
            item("XSS Reflejado DETECTADO - CRÍTICO", "err")
            scanner.deduct_score(25, "XSS Reflejado")
        else:
            item("No se refleja payload XSS", "ok")
    except Exception:
        item("No se pudo probar XSS", "warn")
