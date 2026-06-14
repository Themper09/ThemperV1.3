import socket
import ssl
from src.core.colors import item, C, W, box


def check_ssl(domain):
    box("Certificado SSL/TLS")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issued_to = dict(x[0] for x in cert.get('subject', []))
            issued_by = dict(x[0] for x in cert.get('issuer', []))
            item(f"Emitido para: {C}{issued_to.get('commonName', 'N/A')}{W}", "ok")
            item(f"Emisor: {C}{issued_by.get('organizationName', 'N/A')}{W}", "ok")
            item(f"Válido hasta: {C}{cert.get('notAfter')}{W}", "ok")
        return True
    except Exception:
        item("SSL Timeout normal en CDNs", "warn")
        return False
