import re
import requests
from src.core.colors import item, R, W, box


def check_sourcemaps(html, url, scanner, session=None):
    box("Source Maps Expuestos", R)
    js_urls = re.findall(r'<script.*?src="([^"]+\.js)"', html)
    exposed = 0
    http = session or requests

    for js_url in js_urls[:3]:
        try:
            full_url = js_url if js_url.startswith('http') else url.rstrip('/') + '/' + js_url.lstrip('/')
            map_url = full_url + '.map'
            r = http.get(map_url, timeout=2)
            if r.status_code == 200 and '"sources"' in r.text:
                item(f"SourceMap expuesto: {R}{js_url}.map{W}", "err")
                scanner.deduct_score(10, f"SourceMap expuesto {js_url}")
                exposed += 1
        except Exception:
            pass

    if exposed == 0:
        item("No se detectaron sourcemaps públicos", "ok")
