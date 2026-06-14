import requests
from src.core.colors import item, R, Y, C, BOLD, W, box


def check_grid_expuesto(session, url, scanner):
    box("Grids y Paneles Expuestos", R)

    targets = [
        ("Selenium Grid Hub", "/wd/hub", "Selenium"),
        ("Apache Spark", "/", "Spark Master at"),
        ("Hadoop YARN", "/cluster", "YARN ResourceManager"),
        ("Jenkins", "/jenkins", "Jenkins"),
        ("Grafana", "/login", "Grafana"),
        ("Kibana", "/status", "Kibana"),
        ("Jupyter", "/tree", "Jupyter"),
        ("phpMyAdmin", "/phpmyadmin", "phpMyAdmin"),
        ("Adminer", "/adminer", "Adminer"),
        ("Airflow", "/home", "Airflow"),
        ("Kubernetes Dashboard", "/api/v1/namespaces", "kubernetes"),
        ("Consul UI", "/ui", "Consul"),
    ]

    found = 0
    for name, path, keyword in targets:
        try:
            r = session.get(f"{url.rstrip('/')}{path}", timeout=3, allow_redirects=False)
            if r.status_code < 400 and keyword.lower() in r.text.lower():
                item(f"POSIBLE: {R}{name}{W} en {C}{path}{W}", "err")
                scanner.deduct_score(15, f"Grid expuesto: {name}")
                found += 1
        except Exception:
            pass

    if found == 0:
        item("No se detectaron grids o paneles expuestos", "ok")
