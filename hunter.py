"""Expired-domain hunter: GoDaddy auction feed -> prefilter -> Ahrefs -> Wayback -> verdict.

Run a scan from the command line:  python hunter.py
Or start the dashboard:            python server.py
"""
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import date, datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
CONFIG_PATH = os.path.join(ROOT, "config.json")
RESULTS_PATH = os.path.join(ROOT, "docs", "results.json")
INVENTORY = "https://inventory.auctions.godaddy.com/"
AHREFS = "https://api.ahrefs.com/v3"
UA = {"User-Agent": "Mozilla/5.0 (domain-hunter)"}


# ---------- helpers ----------

def load_env():
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def load_config():
    return json.load(open(CONFIG_PATH, encoding="utf-8"))


def http(url, data=None, headers=None, timeout=60, retries=3):
    err = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise
            err = e
        except Exception as e:
            err = e
        time.sleep(15 * (i + 1))  # Wayback refuses connections for a while when throttled
    raise err


def money(s):
    try:
        return float(str(s).replace("$", "").replace(",", ""))
    except ValueError:
        return 0.0


# ---------- step 1: GoDaddy feed ----------

def download_feed(name, log):
    os.makedirs(DATA, exist_ok=True)
    log(f"ดาวน์โหลด {name}.json.zip จาก GoDaddy ...")
    raw = http(INVENTORY + name + ".json.zip", timeout=300)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        doc = json.loads(z.read(z.namelist()[0]).decode("utf-8-sig"))
    items = doc["data"] if isinstance(doc, dict) else doc
    log(f"ได้รายการ {name}: {len(items):,} โดเมน")
    return items


def fetch_all_items(feed_config, log):
    if feed_config in ("all_feeds", "all"):
        feeds = ["expiring_auctions_non_adult", "closeout_listings", "all_biddable_auctions"]
    elif isinstance(feed_config, str):
        feeds = [feed_config]
    else:
        feeds = list(feed_config)

    all_items = []
    seen = set()
    for feed_name in feeds:
        try:
            items = download_feed(feed_name, log)
            for it in items:
                name = (it.get("domainName") or "").strip().lower()
                if name and name not in seen:
                    seen.add(name)
                    all_items.append(it)
        except Exception as e:
            log(f"⚠ โหลดฟีด {feed_name} ไม่สำเร็จ: {e}")
    log(f"รวมโดเมนจากทุกฟีด: {len(all_items):,} โดเมน (ไม่ซ้ำ)")
    return all_items


def prefilter(items, cfg):
    p = cfg["prefilter"]
    tlds = [t.lower().lstrip(".") for t in p.get("tlds", []) if t]
    types = set(p.get("auction_types") or [])
    # feed field -> (min config key, max config key); a max of 0 means "no limit"
    ranges = {
        "domainAge": ("min_age_years", "max_age_years"),
        "majesticTf": ("min_majestic_tf", "max_majestic_tf"),
        "majesticCf": ("min_majestic_cf", "max_majestic_cf"),
        "majesticBacklinks": ("min_majestic_backlinks", "max_majestic_backlinks"),
        "majesticReferringDomains": ("min_majestic_rd", "max_majestic_rd"),
        "semrushAs": ("min_semrush_as", "max_semrush_as"),
    }
    out = []
    for i in items:
        g = lambda k: i.get(k) or 0
        name = i["domainName"].lower()
        sld, tld = name.rsplit(".", 1)
        if i.get("isAdult") or (types and i.get("auctionType") not in types):
            continue
        if tlds and tld not in tlds:
            continue
        if (p.get("no_digits") and re.search(r"\d", sld)) or (p.get("no_hyphens") and "-" in sld):
            continue
        if len(sld) < (p.get("min_length") or 0) or (p.get("max_length") and len(sld) > p["max_length"]):
            continue
        if any(g(f) < (cfg.get(lo) if lo == "min_age_years" else p.get(lo) or 0) or
               ((p.get(hi) or 0) and g(f) > p[hi]) for f, (lo, hi) in ranges.items()):
            continue
        if p.get("max_price") and money(i.get("price")) > p["max_price"]:
            continue
        out.append(i)
    # Majestic ก่อน (ถ้ามี) แล้วตามด้วย Semrush: โดเมนที่ AS สูงส่วนใหญ่มี Majestic TF = 0
    out.sort(key=lambda i: (-(i.get("majesticTf") or 0), -(i.get("semrushAs") or 0),
                            -(i.get("semrushReferringDomains") or 0), -(i.get("majesticReferringDomains") or 0)))
    return out[: p["max_candidates"]]


# ---------- step 2: Ahrefs ----------

class Ahrefs:
    def __init__(self, key):
        self.key = key
        self.units = 0

    def _h(self):
        return {"Authorization": f"Bearer {self.key}", "Accept": "application/json"}

    def get(self, path, **params):
        url = f"{AHREFS}/{path}?{urllib.parse.urlencode(params)}"
        return json.loads(http(url, headers=self._h()))

    def post(self, path, body):
        h = {**self._h(), "Content-Type": "application/json"}
        return json.loads(http(f"{AHREFS}/{path}", data=json.dumps(body).encode(), headers=h))

    def domain_ratings(self, domains):
        out = {}
        for i in range(0, len(domains), 100):
            chunk = domains[i:i + 100]
            r = self.post("batch-analysis/batch-analysis", {
                "select": ["url", "domain_rating", "refdomains", "org_traffic"],
                "targets": [{"url": d, "mode": "subdomains", "protocol": "both"} for d in chunk],
            })
            for t in r.get("targets", []):
                out[t["url"].rstrip("/").lower()] = t
        return out

    def quality_refdomains(self, domain, min_traffic):
        where = {"and": [{"field": "traffic_domain", "is": ["gte", min_traffic]},
                         {"field": "is_spam", "is": ["eq", False]}]}
        r = self.get("site-explorer/refdomains", target=domain, mode="subdomains",
                     history="live", select="domain,domain_rating,traffic_domain",
                     where=json.dumps(where), order_by="traffic_domain:desc", limit=100)
        return r.get("refdomains", [])

    def traffic_history(self, domain, years=5):
        start = (date.today() - timedelta(days=365 * years)).isoformat()
        r = self.get("site-explorer/metrics-history", target=domain, mode="subdomains",
                     date_from=start, history_grouping="monthly", select="date,org_traffic")
        return r.get("metrics", [])

    def keywords_at(self, domain, day):
        r = self.get("site-explorer/organic-keywords", target=domain, mode="subdomains", date=day,
                     select="keyword,best_position,sum_traffic", order_by="sum_traffic:desc", limit=100)
        return r.get("keywords", [])


# ---------- step 3: Wayback ----------

PARKED = re.compile(r"for sale|zum verkauf|domain.*(parked|expired)|apache2 .*default page|"
                    r"one moment, please|index of /|coming soon|hugedomains|dan\.com|afternic|make a free website", re.I)


def wayback(domain, gamble_re):
    rows = json.loads(http(
        f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,statuscode"
        f"&collapse=timestamp:6&filter=!statuscode:-", timeout=60, retries=2) or b"[]")[1:]
    ok = [r for r in rows if r[1] == "200"]
    res = {"snapshots": len(rows), "first_seen": rows[0][0][:8] if rows else None,
           "last_active": None, "gambling": [], "titles": [], "ext_redirects": {}}

    # sample homepage snapshots evenly + the newest ones, newest first
    sample = sorted(set(map(tuple, ok[::max(1, len(ok) // 4)] + ok[-2:])), reverse=True)
    for ts, _ in sample:
        try:
            html = http(f"http://web.archive.org/web/{ts}id_/http://{domain}/", timeout=30, retries=2).decode("utf-8", "ignore")
        except Exception:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""
        res["titles"].append([ts[:8], title])
        time.sleep(1)
        words = sorted({w.lower() for w in gamble_re.findall(html)})
        if words:
            res["gambling"].append([ts[:8], words[:6]])
        if not res["last_active"] and title and not PARKED.search(title) and not words:
            res["last_active"] = ts[:8]

    # 3xx snapshots: where did they point?
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    for ts, sc in [r for r in rows if r[1].startswith("3")][-8:]:
        try:
            opener.open(urllib.request.Request(f"http://web.archive.org/web/{ts}id_/http://{domain}/", headers=UA), timeout=20)
            continue
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
        except Exception:
            continue
        if "/web/" in loc:
            loc = loc.split("/", 5)[-1]
        host = (urllib.parse.urlparse(loc).hostname or "").lower()
        if host and not host.endswith(domain) and "archive.org" not in host:
            res["ext_redirects"].setdefault(host, []).append(f"{ts[:6]}:{sc}")
    return res


# ---------- step 4: verdict ----------

def judge(r, cfg):
    fails, warns = [], []
    if r["age"] < cfg["min_age_years"]:
        fails.append(f"อายุ {r['age']} ปี (< {cfg['min_age_years']})")
    if r.get("gambling_wayback"):
        fails.append("เคยเป็นเว็บพนัน (Wayback)")
    if r.get("gambling_keywords"):
        fails.append("เคยติดคีย์เวิร์ดพนัน: " + ", ".join(r["gambling_keywords"][:3]))
    if r.get("ext_redirects"):
        fails.append("เคย Redirect ไป " + ", ".join(list(r["ext_redirects"])[:2]))

    dr = r.get("dr")
    if dr is not None:
        if dr < cfg["dr_min_relaxed"]:
            fails.append(f"DR {dr:g} (< {cfg['dr_min_relaxed']})")
        elif dr < cfg["dr_min"]:
            warns.append(f"DR {dr:g} (เกณฑ์ผ่อน)")

    q = r.get("quality_count")
    if q is not None:
        if q < cfg["quality_min_relaxed"]:
            fails.append(f"Backlink คุณภาพ {q} (< {cfg['quality_min_relaxed']})")
        elif q < cfg["quality_min"]:
            warns.append(f"Backlink คุณภาพ {q} (เกณฑ์ผ่อน)")

    la = r.get("last_active")
    if r.get("wayback_checked") and cfg.get("active_within_months"):  # 0 = don't check activity
        if not la:
            fails.append("ไม่พบช่วงที่เว็บใช้งานจริง")
        else:
            months = (date.today() - datetime.strptime(la, "%Y%m%d").date()).days / 30.4
            if months > cfg["active_within_months"]:
                fails.append(f"เว็บหยุดใช้งานมา {months:.0f} เดือน")
    if r.get("stage") == "wayback_failed":
        warns.append("ดึงข้อมูล Wayback ไม่สำเร็จ (ลองสแกนใหม่)")
    if r.get("brand_checked") and not r.get("brand_keywords"):
        warns.append("ไม่พบ Brand Search ในอดีต")

    if dr is None:
        warns.append("ยังไม่ได้เช็ก DR/Backlink (ไม่มี Ahrefs key)")
    r["fails"], r["warns"] = fails, warns
    pending = r.get("stage") != "done" or dr is None
    r["verdict"] = "fail" if fails else ("pending" if pending else ("relaxed" if warns else "pass"))
    return r


# ---------- pipeline ----------

def brand_of(domain):
    return re.sub(r"[^a-z0-9]", "", domain.rsplit(".", 1)[0].lower())


def deep_check(r, ah, cfg, gamble_re):
    d = r["domain"]
    if ah:
        refs = ah.quality_refdomains(d, cfg["quality_traffic_min"])
        r["quality_count"] = len(refs)
        r["quality_top"] = [[x["domain"], x["domain_rating"], x["traffic_domain"]] for x in refs[:25]]
        r["edu_wiki"] = [x["domain"] for x in refs if re.search(r"wikipedia|\.edu|\.ac\.|\.gov", x["domain"])]

        hist = ah.traffic_history(d)
        if hist:
            peak = max(hist, key=lambda h: h.get("org_traffic") or 0)
            r["peak_traffic"], r["peak_date"] = peak.get("org_traffic") or 0, peak["date"][:10]
            r["traffic_history"] = [[h["date"][:7], h.get("org_traffic") or 0] for h in hist]
            kws = ah.keywords_at(d, r["peak_date"]) if r["peak_traffic"] else []
            r["top_keywords"] = [[k["keyword"], k["best_position"], k.get("sum_traffic") or 0] for k in kws[:20]]
            r["gambling_keywords"] = [k["keyword"] for k in kws if gamble_re.search(k["keyword"])]
            b = brand_of(d)
            # a brand search contains the whole name, e.g. "park grill chicago" or "stop spanking"
            r["brand_keywords"] = list(dict.fromkeys(
                k["keyword"] for k in kws if len(b) >= 4 and b in re.sub(r"[^a-z0-9]", "", k["keyword"].lower())))
            r["brand_checked"] = True

    return wayback_check(r, gamble_re)


def wayback_check(r, gamble_re):
    """แยกออกมาเพื่อให้ลองใหม่ได้โดยไม่ต้องเรียก Ahrefs ซ้ำ (เสียโควต้า)"""
    d = r["domain"]
    try:
        wb = wayback(d, gamble_re)
    except Exception as e:
        r["error"] = describe(e)
        r["stage"] = "wayback_failed"
        return r
    r.pop("error", None)
    # no snapshot page could be fetched although snapshots exist -> Wayback throttled us; don't judge on it
    fetched = bool(wb["titles"]) or wb["snapshots"] == 0
    r.update(first_seen=wb["first_seen"], last_active=wb["last_active"], titles=wb["titles"],
             gambling_wayback=wb["gambling"], ext_redirects=wb["ext_redirects"], wayback_checked=fetched)
    r["stage"] = "done" if fetched else "wayback_failed"
    return r


def gambling_regex(cfg):
    # whole words for Latin terms (so "toto" doesn't hit "totoro"); Thai has no word spaces
    parts = [rf"\b{re.escape(w)}(?:s|\d+)?\b" if w.isascii() else re.escape(w) for w in cfg["gambling_words"]]
    return re.compile("|".join(parts), re.I)



def notify_webhook(r, mins_left, cfg=None):
    """ส่งแจ้งเตือนผ่าน Discord Webhook / Telegram / LINE เมื่อใกล้หมดเวลาประมูล"""
    cfg = cfg or load_config()
    notify_cfg = cfg.get("notify") or {}
    discord_url = os.environ.get("DISCORD_WEBHOOK_URL") or notify_cfg.get("discord_webhook_url")
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN") or notify_cfg.get("telegram_bot_token")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID") or notify_cfg.get("telegram_chat_id")
    line_token = os.environ.get("LINE_NOTIFY_TOKEN") or notify_cfg.get("line_token")

    domain = r.get("domain", "")
    price = r.get("price", 0)
    bids = r.get("bids", 0)
    dr = r.get("dr", "–")
    link = r.get("link") or f"https://www.godaddy.com/domain-auctions"
    msg = f"⏰ [เตือนใกล้หมดเวลาประมูล] {domain}\nเหลือเวลาอีกประมาณ {mins_left} นาที!\nราคา: ${price:g} ({bids} บิด) · DR: {dr}\nลิงก์: {link}"

    if discord_url:
        try:
            payload = {
                "content": f"⏰ **แจ้งเตือนโดเมนใกล้หมดเวลาประมูล!**",
                "embeds": [{
                    "title": f"🔔 {domain}",
                    "url": link,
                    "color": 15105570,
                    "fields": [
                        {"name": "เวลาที่เหลือ", "value": f"⚡ อีก {mins_left} นาที", "inline": True},
                        {"name": "ราคาปัจจุบัน", "value": f"${price:g} ({bids} บิด)", "inline": True},
                        {"name": "DR", "value": str(dr), "inline": True}
                    ]
                }]
            }
            http(discord_url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, timeout=10)
        except Exception as e:
            print(f"Discord webhook error: {e}")

    if tg_token and tg_chat:
        for attempt in range(3):
            try:
                tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
                payload = {"chat_id": tg_chat, "text": msg}
                http(tg_url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, timeout=25)
                break
            except Exception as e:
                if attempt == 2:
                    print(f"Telegram notify error: {e}")

    if line_token:
        try:
            line_url = "https://notify-api.line.me/api/notify"
            body = urllib.parse.urlencode({"message": "\n" + msg}).encode("utf-8")
            http(line_url, data=body, headers={"Authorization": f"Bearer {line_token}"}, timeout=10)
        except Exception as e:
            print(f"LINE notify error: {e}")


def auction_ended(r, now):
    end = r.get("end_time")
    if not end:
        return False
    try:
        return datetime.fromisoformat(end.replace("Z", "+00:00")) <= now
    except ValueError:
        return False


def load_wayback_retry():
    """โดเมนที่ Wayback ไม่ตอบในรอบก่อน (เก็บไว้ใน results.json พร้อมข้อมูล Ahrefs ที่ดึงแล้ว)"""
    if not os.path.exists(RESULTS_PATH):
        return []
    try:
        return json.load(open(RESULTS_PATH, encoding="utf-8")).get("wayback_retry", [])
    except Exception:
        return []


def run_scan(log=print):
    load_env()
    cfg = load_config()
    gamble_re = gambling_regex(cfg)
    key = os.environ.get("AHREFS_API_KEY", "").strip()
    ah = Ahrefs(key) if key else None
    if not ah:
        log("⚠ ไม่มี AHREFS_API_KEY ใน .env — ข้ามขั้น DR/Backlink/Keyword (เช็กแค่ Wayback)")

    items = fetch_all_items(cfg.get("source_feed", "expiring_auctions_non_adult"), log)
    cands = prefilter(items, cfg)
    log(f"กรองรอบแรก (อายุ/Majestic/ราคา) เหลือ {len(cands)} โดเมน")

    results = []
    for i in cands:
        results.append({
            "domain": i["domainName"].lower(), "link": i.get("link"), "price": money(i.get("price")),
            "bids": i.get("numberOfBids") or 0, "end_time": i.get("auctionEndTime"),
            "age": i.get("domainAge") or 0, "majestic_tf": i.get("majesticTf") or 0,
            "majestic_rd": i.get("majesticReferringDomains") or 0, "stage": "prefilter",
        })

    if ah:
        log("ดึง DR จาก Ahrefs ...")
        try:
            drs = ah.domain_ratings([r["domain"] for r in results])
            log(f"Ahrefs ใช้งานได้ ได้ DR {len(drs)} โดเมน")
        except Exception as e:
            log(f"❌ เรียก Ahrefs ไม่สำเร็จ: {describe(e)} — สแกนต่อแบบไม่มี Ahrefs")
            ah = None
    if ah:
        for r in results:
            t = drs.get(r["domain"], {})
            r["dr"], r["refdomains"] = t.get("domain_rating"), t.get("refdomains")
        deep = [r for r in results if (r["dr"] or 0) >= cfg["dr_min_relaxed"]]
        for r in results:
            if r not in deep:
                r["stage"] = "dr"
    else:
        deep = results[: cfg.get("max_deep_without_ahrefs", 15)]
        for r in results[len(deep):]:
            r["stage"] = "prefilter"
    def report(r):
        if r.get("stage") == "wayback_failed":
            log(f"  {r['domain']}: Wayback ไม่ตอบ {r.get('error', '')}")
        else:
            log(f"  {r['domain']}: {r['verdict']} {'; '.join(r['fails'] or r['warns'])}")

    # โดเมนที่ Wayback ล้มเหลวจากรอบก่อน: ข้อมูล Ahrefs มีแล้ว เช็กแค่ Wayback ใหม่
    now = datetime.now(timezone.utc)
    this_round = {r["domain"] for r in deep}
    carried = [r for r in load_wayback_retry() if r["domain"] not in this_round and not auction_ended(r, now)]
    if carried:
        log(f"ลอง Wayback ใหม่ {len(carried)} โดเมนที่ค้างจากรอบก่อน ...")
        for r in carried:
            wayback_check(r, gamble_re)
            judge(r, cfg)
            report(r)
            time.sleep(5)

    log(f"เช็กเชิงลึก {len(deep)} โดเมน (Backlink, Keyword ย้อนหลัง, Wayback) ...")
    # ทีละโดเมน: Wayback ปฏิเสธการเชื่อมต่อ (Connection refused) เมื่อยิงพร้อมกันหลายตัว
    for r in deep:
        try:
            deep_check(r, ah, cfg, gamble_re)
        except Exception as e:  # Ahrefs ล้มเหลว
            r["error"] = describe(e)
            r["stage"] = "ahrefs_failed"
        judge(r, cfg)
        report(r)
        time.sleep(5)

    failed = [r for r in deep + carried if r.get("stage") == "wayback_failed"]
    if failed:
        log(f"รอ Wayback 2 นาที แล้วลองใหม่ {len(failed)} โดเมน ...")
        time.sleep(120)
        for r in failed:
            wayback_check(r, gamble_re)
            judge(r, cfg)
            report(r)
            time.sleep(10)
    still_failed = [r for r in deep + carried if r.get("stage") == "wayback_failed"]
    if still_failed:
        log(f"⚠ Wayback ยังไม่ตอบ {len(still_failed)} โดเมน — จะลองใหม่รอบสแกนถัดไป")

    for r in results:
        if r not in deep:
            judge(r, cfg)
    results += carried

    # กรองเฉพาะโดเมนที่ผ่านเกณฑ์ (pass หรือ relaxed) ในรอบนี้
    this_passed = [r for r in results if r.get("verdict") in ("pass", "relaxed")]

    # สะสมผลลัพธ์จากรอบก่อนหน้าที่ยังไม่หมดเวลาประมูล
    accumulated = {}
    now = datetime.now(timezone.utc)
    if os.path.exists(RESULTS_PATH):
        try:
            old_data = json.load(open(RESULTS_PATH, "r", encoding="utf-8"))
            for old_r in old_data.get("results", []):
                if old_r.get("verdict") in ("pass", "relaxed"):
                    # ตรวจสอบว่าหมดเวลาประมูลหรือยัง (ถ้ามี end_time)
                    end = old_r.get("end_time")
                    if end:
                        try:
                            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                            if end_dt < now:
                                continue  # ประมูลจบแล้ว คัดออก
                        except Exception:
                            pass
                    accumulated[old_r["domain"].lower()] = old_r
        except Exception as e:
            log(f"⚠ อ่านผลสแกนเดิมไม่สำเร็จ: {e}")

    # รวมผลลัพธ์รอบล่าสุดเข้ากับที่สะสมไว้
    for r in this_passed:
        accumulated[r["domain"].lower()] = r

    # คัดเฉพาะโดเมนที่ผ่านเกณฑ์และยังไม่หมดเวลาประมูลเท่านั้น
    final_results = []
    for r in accumulated.values():
        end = r.get("end_time")
        if end:
            try:
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                if end_dt <= now:
                    continue  # หมดเวลาประมูลแล้ว คัดทิ้งทันที
            except Exception:
                pass
        final_results.append(r)

    order = {"pass": 0, "relaxed": 1}
    final_results.sort(key=lambda r: (order.get(r.get("verdict"), 9), -(r.get("dr") or 0), -(r.get("majestic_tf") or 0)))

    # ตรวจสอบรายการที่ใกล้หมดเวลาประมูลภายใน 20 นาที เพื่อส่งแจ้งเตือน
    for r in final_results:
        end = r.get("end_time")
        if end:
            try:
                end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
                diff_mins = (end_dt - now).total_seconds() / 60
                if 0 < diff_mins <= 20:
                    log(f"⏰ [ใกล้หมดเวลา] {r['domain']} เหลืออีก {int(diff_mins)} นาที!")
                    notify_webhook(r, int(diff_mins), cfg)
            except Exception:
                pass

    feed_val = cfg.get("source_feed", "expiring_auctions_non_adult")
    feed_label = feed_val if isinstance(feed_val, str) else ", ".join(feed_val)
    out = {"scanned_at": now.isoformat(timespec="seconds"),
           "feed": feed_label, "feed_total": len(items), "results": final_results,
           "wayback_retry": still_failed}
    json.dump(out, open(RESULTS_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    # สำเนานี้ถูกเผยแพร่บน GitHub Pages: ห้ามมีข้อมูลแจ้งเตือน/token
    public_cfg = {k: v for k, v in cfg.items() if k != "notify"}
    json.dump(public_cfg, open(os.path.join(ROOT, "docs", "config.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    log(f"เสร็จแล้ว: ผ่านสะสม {len(final_results)} โดเมน (รอบนี้พบใหม่ {len(this_passed)} โดเมน) · ไม่บันทึกรายการที่ไม่ผ่าน")
    return out


def describe(e):
    if isinstance(e, urllib.error.HTTPError):
        try:
            body = e.read().decode("utf-8", "ignore")[:300]
        except Exception:
            body = ""
        return f"HTTP {e.code} {body}"
    return f"{type(e).__name__}: {e}"


if __name__ == "__main__":
    # CLI / GitHub Actions: also keep the log in docs/scan_log.txt so it is visible on the website
    import traceback
    lines = []

    def file_log(msg):
        line = f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} {msg}"
        print(line, flush=True)
        lines.append(line)
        open(os.path.join(ROOT, "docs", "scan_log.txt"), "w", encoding="utf-8").write("\n".join(lines))

    try:
        run_scan(file_log)
    except Exception as e:
        file_log(f"❌ สแกนล้มเหลว: {describe(e)}")
        file_log(traceback.format_exc())
        raise SystemExit(1)
