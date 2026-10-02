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
from concurrent.futures import ThreadPoolExecutor
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
        time.sleep(3 * (i + 1))
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
    log(f"ได้รายการทั้งหมด {len(items):,} โดเมน")
    return items


def prefilter(items, cfg):
    p = cfg["prefilter"]
    tlds = [t.lower().lstrip(".") for t in p.get("tlds", []) if t]
    out = []
    for i in items:
        g = lambda k: i.get(k) or 0
        name = i["domainName"].lower()
        if g("domainAge") < cfg["min_age_years"] or i.get("isAdult"):
            continue
        if tlds and name.rsplit(".", 1)[-1] not in tlds:
            continue
        if g("majesticTf") < p["min_majestic_tf"] or g("majesticReferringDomains") < p["min_majestic_rd"]:
            continue
        if p.get("max_price") and money(i.get("price")) > p["max_price"]:
            continue
        out.append(i)
    out.sort(key=lambda i: (-(i.get("majesticTf") or 0), -(i.get("majesticReferringDomains") or 0)))
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
        r = self.get("site-explorer/referring-domains", target=domain, mode="subdomains",
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
                    r"one moment, please|index of /|coming soon|hugedomains|dan\.com|afternic", re.I)


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
            html = http(f"http://web.archive.org/web/{ts}id_/http://{domain}/", timeout=25, retries=1).decode("utf-8", "ignore")
        except Exception:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""
        res["titles"].append([ts[:8], title])
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
    if r.get("wayback_checked"):
        if not la:
            fails.append("ไม่พบช่วงที่เว็บใช้งานจริง")
        else:
            months = (date.today() - datetime.strptime(la, "%Y%m%d").date()).days / 30.4
            if months > cfg["active_within_months"]:
                fails.append(f"เว็บหยุดใช้งานมา {months:.0f} เดือน")
    if r.get("brand_checked") and not r.get("brand_keywords"):
        warns.append("ไม่พบ Brand Search ในอดีต")

    r["fails"], r["warns"] = fails, warns
    pending = r.get("stage") != "done"
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
            r["brand_keywords"] = [k["keyword"] for k in kws
                                   if len(b) >= 4 and (b in k["keyword"].replace(" ", "") or
                                                       (len(k["keyword"]) >= 4 and k["keyword"].replace(" ", "") in b))]
            r["brand_checked"] = True

    wb = wayback(d, gamble_re)
    r.update(first_seen=wb["first_seen"], last_active=wb["last_active"], titles=wb["titles"],
             gambling_wayback=wb["gambling"], ext_redirects=wb["ext_redirects"], wayback_checked=True)
    r["stage"] = "done"
    return r


def run_scan(log=print):
    load_env()
    cfg = load_config()
    gamble_re = re.compile("|".join(cfg["gambling_words"]), re.I)
    key = os.environ.get("AHREFS_API_KEY", "").strip()
    ah = Ahrefs(key) if key else None
    if not ah:
        log("⚠ ไม่มี AHREFS_API_KEY ใน .env — ข้ามขั้น DR/Backlink/Keyword (เช็กแค่ Wayback)")

    items = download_feed(cfg["source_feed"], log)
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
        drs = ah.domain_ratings([r["domain"] for r in results])
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
    log(f"เช็กเชิงลึก {len(deep)} โดเมน (Backlink, Keyword ย้อนหลัง, Wayback) ...")

    def work(r):
        try:
            deep_check(r, ah, cfg, gamble_re)
            judge(r, cfg)
            log(f"  {r['domain']}: {r['verdict']} {'; '.join(r['fails'] or r['warns'])}")
        except Exception as e:
            r["error"] = str(e)
            log(f"  {r['domain']}: error {e}")
        return r

    with ThreadPoolExecutor(3) as ex:
        list(ex.map(work, deep))
    for r in results:
        if r not in deep:
            judge(r, cfg)

    order = {"pass": 0, "relaxed": 1, "pending": 2, "fail": 3}
    results.sort(key=lambda r: (order[r["verdict"]], -(r.get("dr") or 0)))
    out = {"scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "feed": cfg["source_feed"], "feed_total": len(items), "results": results}
    json.dump(out, open(RESULTS_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(cfg, open(os.path.join(ROOT, "docs", "config.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    n = sum(r["verdict"] in ("pass", "relaxed") for r in results)
    log(f"เสร็จแล้ว: ผ่าน {n} โดเมน จาก {len(results)} ที่เช็ก")
    return out


if __name__ == "__main__":
    run_scan()
