import re
import requests
from src.core.colors import item, G, Y, DIM, W, box


def check_robots_sitemap(session, url, scanner):
    box("robots.txt & sitemap.xml")
    for file in ['robots.txt', 'sitemap.xml']:
        try:
            r = session.get(f"{url}/{file}", timeout=2)
            if r.status_code == 200 and not scanner.is_catchall(r.text):
                lines = len(r.text.split('\n'))
                item(f"{file}: {G}Encontrado{W} - {lines} líneas", "ok")
                print(f"{DIM}{r.text[:300]}...{W}")
                if file == 'robots.txt' and 'Disallow' in r.text:
                    disallow = re.findall(r'Disallow: (.+)', r.text)
                    if disallow:
                        item(f"Rutas ocultas: {Y}{', '.join(disallow[:5])}{W}", "warn")
            else:
                item(f"{file}: No encontrado o es catch-all", "info")
        except Exception:
            pass
