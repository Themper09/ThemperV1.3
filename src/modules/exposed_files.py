import requests
from src.core.colors import item, Y, R, DIM, W, box


def check_exposed_files(url, scanner):
    box("Archivos Sensibles Expuestos", R)
    sensitive = ['.env', '.git/config', '.DS_Store', 'wp-config.php',
                 'config.json', 'backup.zip', 'database.sql', '.htaccess',
                 'phpinfo.php']
    found = 0

    for file in sensitive:
        try:
            r = requests.get(f"{url}/{file}", timeout=3, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 20:
                if scanner.is_catchall(r.text):
                    item(f"{file}: {Y}Catch-all detectado{W}", "warn")
                else:
                    item(f"CRÍTICO: {R}{file} expuesto{W}", "err")
                    scanner.deduct_score(30, f"{file} público")
                    print(f"{DIM}Contenido: {r.text[:200]}...{W}")
                    found += 1
        except Exception:
            pass

    if found == 0:
        item("No se encontraron archivos sensibles expuestos reales", "ok")
