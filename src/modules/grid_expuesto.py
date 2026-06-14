import requests
from src.core.colors import item, R, Y, C, BOLD, W, box


def check_grid_expuesto(url, scanner):
    box("Grids y Paneles Expuestos", R)

    targets = [
        ("Selenium Grid Hub", "/wd/hub", "Selenium"),
        ("Selenium Grid Console", "/grid/console", "Grid Console"),
        ("Apache Spark Master", "/", "Spark Master at"),
        ("Apache Spark Worker", "/", "Spark Worker at"),
        ("Hadoop YARN RM", "/cluster", "YARN ResourceManager"),
        ("Hadoop YARN NM", "/nodemanager", "Node Manager"),
        ("Jenkins", "/jenkins", "Jenkins"),
        ("Jenkins Alt", "/", "Jenkins["),
        ("Grafana", "/login", "Grafana"),
        ("Kibana", "/status", "Kibana"),
        ("Jupyter", "/tree", "Jupyter"),
        ("Jupyter Lab", "/lab", "JupyterLab"),
        ("phpMyAdmin", "/phpmyadmin", "phpMyAdmin"),
        ("phpMyAdmin Alt", "/pma", "phpMyAdmin"),
        ("Adminer", "/adminer", "Adminer"),
        ("pgAdmin", "/pgadmin", "pgAdmin"),
        ("Airflow", "/home", "Airflow"),
        ("Kubernetes Dashboard", "/api/v1/namespaces", "kubernetes"),
        ("Consul UI", "/ui", "Consul"),
        ("RabbitMQ", "/api/index.html", "RabbitMQ"),
    ]

    found = 0
    for name, path, keyword in targets:
        try:
            r = requests.get(f"{url.rstrip('/')}{path}", timeout=4, allow_redirects=False)
            if r.status_code < 400 and keyword.lower() in r.text.lower():
                item(f"POSIBLE: {R}{name}{W} en {C}{path}{W}", "err")
                scanner.deduct_score(15, f"Grid expuesto: {name}")
                found += 1
        except Exception:
            pass

    if found == 0:
        item("No se detectaron grids o paneles expuestos", "ok")
