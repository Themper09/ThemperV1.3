import re
import requests
from src.core.colors import item, R, C, W, box


def scan_js_secrets(html, url, scanner, session=None):
    box("Secrets en Frontend", R)
    js_urls = re.findall(r'<script.*?src="([^"]+\.js)"', html)
    patterns = {
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'Google API': r'AIza[0-9A-Za-z\-_]{35}',
        'Stripe Live': r'sk_live_[0-9a-zA-Z]{24}',
        'Stripe Test': r'sk_test_[0-9a-zA-Z]{24}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'Generic Secret': r'["\']?[a-zA-Z0-9_]*secret[a-zA-Z0-9_]*["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']'
    }
    http = session or requests

    found = 0
    for js_url in js_urls[:3]:
        try:
            full_url = js_url if js_url.startswith('http') else url.rstrip('/') + '/' + js_url.lstrip('/')
            js = http.get(full_url, timeout=3).text
            for name, pattern in patterns.items():
                matches = re.findall(pattern, js)
                if matches:
                    item(f"Posible {R}{name} filtrado{W} en {js_url}", "err")
                    item(f"Match: {C}{matches[0][:30]}...{W}", "info")
                    scanner.deduct_score(20, f"{name} en JS")
                    found += 1
        except Exception:
            pass

    if found == 0:
        item("No se detectaron secrets obvios en JS", "ok")
