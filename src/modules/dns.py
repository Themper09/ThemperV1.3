import json
import requests
from src.core.colors import item, C, W


def get_dns_doh(session, domain, record_type):
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
        headers = {"accept": "application/dns-json"}
        r = session.get(url, headers=headers, timeout=4)
        data = r.json()
        item(f"DNS DoH Raw {record_type}: {C}{json.dumps(data)[:80]}...{W}", "info")
        if "Answer" in data:
            for answer in data["Answer"]:
                item(f"{record_type}: {C}{answer['data']}{W}", "ok")
        else:
            item(f"No hay registros {record_type} públicos", "warn")
    except Exception as e:
        item(f"Error DNS {record_type}: {e}", "err")
