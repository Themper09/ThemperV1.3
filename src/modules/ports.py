import socket
from src.core.colors import item, G, Y, W, box


def scan_ports(ip):
    box("Escaneo de Puertos", Y)
    item("IPs anycast solo exponen 80/443", "warn")
    for p, servicio in {80: 'HTTP', 443: 'HTTPS'}.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            if s.connect_ex((ip, p)) == 0:
                item(f"Puerto {p} ({servicio}): {G}Abierto{W}", "ok")
        except Exception:
            pass
        finally:
            s.close()
