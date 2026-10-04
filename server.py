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



def monitor_loop():
    """คอยตรวจสอบทุก 30 วินาที: คัดโดเมนที่หมดเวลาออก และส่งแจ้งเตือนก่อน 20 นาที"""
    import time
    from datetime import timezone
    notified = set()
    while True:
        time.sleep(30)
        try:
            p = hunter.RESULTS_PATH
            if not os.path.exists(p):
                continue
            data = json.load(open(p, encoding="utf-8"))
            results = data.get("results", [])
            now = datetime.now(timezone.utc)
            modified = False
            active = []

            for r in results:
                end = r.get("end_time")
                if end:
                    try:
                        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        # 1. คัดรายการที่หมดเวลาประมูลแล้วออกไป
                        if end_dt <= now:
                            log(f"⌛ หมดเวลาประมูล: นำ {r['domain']} ออกจากตารางเรียบร้อย")
                            modified = True
                            continue
                        # 2. แจ้งเตือนเมื่อเหลือเวลา 0-20 นาที
                        diff_mins = (end_dt - now).total_seconds() / 60
                        if 0 < diff_mins <= 20 and r["domain"] not in notified:
                            notified.add(r["domain"])
                            log(f"⏰ [เตือนประมูล] โดเมน {r['domain']} เหลือเวลาอีกประมาณ {int(diff_mins)} นาที!")
                            hunter.notify_webhook(r, int(diff_mins))
                    except Exception:
                        pass
                active.append(r)

            if modified:
                data["results"] = active
                json.dump(data, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        except Exception:
            pass


if __name__ == "__main__":
    hunter.load_env()  # ให้ monitor_loop อ่าน TELEGRAM_BOT_TOKEN จาก .env ได้
    threading.Thread(target=monitor_loop, daemon=True).start()
    print(f"Dashboard: http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
