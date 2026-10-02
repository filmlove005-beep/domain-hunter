"""Dashboard server. Run: python server.py  then open http://localhost:8765"""
import json
import os
import threading
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import hunter

PORT = 8765
STATE = {"running": False, "log": []}


def log(msg):
    STATE["log"].append(f"{datetime.now():%H:%M:%S} {msg}")
    STATE["log"] = STATE["log"][-300:]
    print(msg, flush=True)


def scan():
    try:
        hunter.run_scan(log)
    except Exception as e:
        log(f"❌ ผิดพลาด: {e}")
    finally:
        STATE["running"] = False


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=os.path.join(hunter.ROOT, "docs"), **k)

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/results":
            p = hunter.RESULTS_PATH
            return self.send_json(json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {"results": []})
        if self.path == "/api/config":
            return self.send_json(hunter.load_config())
        if self.path == "/api/status":
            return self.send_json(STATE)
        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/config":
            cfg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            json.dump(cfg, open(hunter.CONFIG_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
            return self.send_json({"ok": True})
        if self.path == "/api/scan":
            if not STATE["running"]:
                STATE.update(running=True, log=[])
                threading.Thread(target=scan, daemon=True).start()
            return self.send_json({"ok": True})
        self.send_error(404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"Dashboard: http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
