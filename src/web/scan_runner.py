import io
import os
import sys
import time
import threading
import queue
from urllib.parse import urlparse

from src.core.scanner import ThemperV1


class CaptureOutput(io.StringIO):
    def __init__(self, q):
        super().__init__()
        self.q = q

    def write(self, s):
        if s.strip():
            self.q.put(s)
        super().write(s)

    def flush(self):
        pass


class ScanRunner:
    def __init__(self):
        self.scans = {}

    def start_scan(self, scan_id, url, export=True):
        q = queue.Queue()
        self.scans[scan_id] = {
            "queue": q,
            "done": False,
            "result": None,
            "url": url,
            "export": export,
        }

        thread = threading.Thread(target=self._run, args=(scan_id, url, q, export), daemon=True)
        thread.start()
        return scan_id

    def _run(self, scan_id, url, q, export=True):
        scanner = ThemperV1()
        old_stdout = sys.stdout
        sys.stdout = CaptureOutput(q)

        try:
            export_mode = 'yes' if export else 'no'
            exit_code = scanner.run(url, export=export_mode)
            parsed = urlparse(url)
            domain = parsed.netloc
            domain_clean = domain.replace('.', '_').replace(':', '_')
            result = {
                "score": max(0, scanner.score),
                "vulns": list(scanner.vulns),
                "risk_level": (
                    "LOW" if scanner.score >= 70
                    else "MEDIUM" if scanner.score >= 50
                    else "HIGH"
                ),
                "duration": round(time.time() - scanner.start_time, 2),
                "exit_code": exit_code,
                "domain": domain,
                "html_report": os.path.abspath(f"themper_{domain_clean}.html"),
                "json_report": os.path.abspath(f"themper_{domain_clean}.json"),
            }
        except Exception as e:
            result = {
                "score": 0,
                "vulns": [str(e)],
                "risk_level": "ERROR",
                "duration": 0,
                "exit_code": 1,
                "domain": "",
                "error": str(e),
            }
            q.put(f"[ERROR] {e}")
        finally:
            sys.stdout = old_stdout
            if scan_id in self.scans:
                self.scans[scan_id]["done"] = True
                self.scans[scan_id]["result"] = result

    def get_queue(self, scan_id):
        scan = self.scans.get(scan_id)
        return scan["queue"] if scan else None

    def is_done(self, scan_id):
        scan = self.scans.get(scan_id)
        return scan["done"] if scan else False

    def get_result(self, scan_id):
        scan = self.scans.get(scan_id)
        return scan["result"] if scan else None

    def cleanup(self, scan_id):
        if scan_id in self.scans:
            del self.scans[scan_id]
