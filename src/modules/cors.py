import requests
from src.core.colors import item, Y, W, box


def check_cors(url, scanner):
    box("CORS Misconfiguration", Y)
    try:
        headers = {'Origin': 'https://evil.com'}
        r = requests.get(url, headers=headers, timeout=5)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*':
            item("Access-Control-Allow-Origin: * detectado", "warn")
            scanner.deduct_score(5, "CORS wildcard")
        elif acao == 'https://evil.com':
            item("CRÍTICO: CORS refleja Origin malicioso", "err")
            scanner.deduct_score(20, "CORS refleja Origin")

        if acac.lower() == 'true' and acao == '*':
            item("CRÍTICO: ACAO:* + ACAC:true = exploit", "err")
            scanner.deduct_score(25, "CORS + Credentials wildcard")
        else:
            item("CORS parece seguro", "ok")
    except Exception:
        item("No se pudo probar CORS", "warn")
