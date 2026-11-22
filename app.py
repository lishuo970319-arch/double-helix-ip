import concurrent.futures
import http.server
import ipaddress
import json
import os
import pathlib
import re
import socket
import socketserver
import statistics
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if getattr(sys, "frozen", False):
    BUNDLE_DIR = pathlib.Path(sys._MEIPASS)
    RUNTIME_DIR = pathlib.Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = pathlib.Path(__file__).resolve().parent
    RUNTIME_DIR = BUNDLE_DIR

INDEX_FILE = BUNDLE_DIR / "index.html"
LAND_FILE = BUNDLE_DIR / "land110.txt"
HISTORY_FILE = RUNTIME_DIR / "ip_check_history.json"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36"
)
CURL_HDR = {"User-Agent": "curl/8.12.1"}

JOBS = {}
LOCK = threading.Lock()

DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN", "Spam"),
    ("bl.spamcop.net", "SpamCop", "Spam"),
    ("b.barracudacentral.org", "Barracuda BRBL", "Spam"),
    ("dnsbl.sorbs.net", "SORBS", "Spam"),
    ("cbl.abuseat.org", "CBL Abuseat", "Botnet"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT L1", "Spam"),
    ("dnsbl-2.uceprotect.net", "UCEPROTECT L2", "Spam"),
    ("psbl.surriel.com", "PSBL Surriel", "Spam"),
    ("ubl.unsubscore.com", "Lashback UBL", "Spam"),
    ("dnsbl.dronebl.org", "DroneBL", "Botnet"),
    ("bl.mailspike.net", "Mailspike BL", "Reputation"),
    ("z.mailspike.net", "Mailspike Z", "Spam"),
    ("all.s5h.net", "S5H All", "Reputation"),
    ("bl.0spam.org", "0spam Main", "Spam"),
    ("spam.dnsbl.anonmails.de", "Anonmails DE", "Spam"),
    ("bl.blocklist.de", "Blocklist.de", "Botnet"),
    ("rbl.interserver.net", "InterServer RBL", "Reputation"),
    ("db.wpbl.info", "WPBL", "Spam"),
    ("hostkarma.junkemailfilter.com", "HostKarma", "Reputation"),
    ("ix.dnsbl.manitu.net", "NiX Spam", "Spam"),
    ("korea.services.net", "Korea Services", "Spam"),
    ("rbl.realtimeblacklist.com", "RealtimeBL", "Reputation"),
    ("relays.nether.net", "Nether Relays", "Proxy/Tor"),
    ("spam.spamrats.com", "SpamRATS Spam", "Spam"),
    ("noptr.spamrats.com", "SpamRATS NoPTR", "Reputation"),
    ("dyna.spamrats.com", "SpamRATS Dyna", "Reputation"),
    ("truncate.gbudb.net", "GBUdb Truncate", "Malware"),
    ("bl.nordspam.com", "NordSpam", "Spam"),
    ("dnsbl.justspam.org", "JustSpam", "Spam"),
    ("tor.dan.me.uk", "Dan.me.uk Tor", "Proxy/Tor"),
]

ANTHROPIC_BLOCKED_CC = {"CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "VE"}
GLOBAL_PING_NODES = [
    ("n01", "cn", "上海"),
    ("n02", "hk", "香港"),
    ("n03", "jp", "东京"),
    ("n04", "sg", "新加坡"),
    ("n09", "us", "洛杉矶"),
    ("n11", "ca", "温哥华"),
    ("n13", "de", "法兰克福"),
    ("n15", "fr", "巴黎"),
]

# 全球主流宽带运营商 / 骨干网 / 机房百科词典（纯客观身份科普，不含任何自创评分）
ASN_ENCYCLOPEDIA = {
    "AS7922": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Comcast Xfinity", "desc": "全美最大有线电视与家庭宽带运营商，正宗居民入户宽带网段"},
    "AS7015": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Comcast 区域网", "desc": "Comcast 旗下区域居民宽带接入网"},
    "AS33659": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Comcast 区域网", "desc": "Comcast 旗下区域居民宽带接入网"},
    "AS20115": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Spectrum (Charter)", "desc": "全美第二大有线家庭宽带运营商 Charter 旗下居民入户宽带"},
    "AS11426": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Spectrum (Charter)", "desc": "Charter / Spectrum 东海岸主力居民家宽网段"},
    "AS7843": {"kind": "isp", "tag": "🇺🇸 美国头部正规家宽", "brand": "Spectrum (老时代华纳段)", "desc": "Spectrum 并购原 Time Warner Cable 延续的居民宽带段"},
    "AS7018": {"kind": "isp", "tag": "🇺🇸 美国顶级光纤/家宽", "brand": "AT&T Internet", "desc": "美国老牌电信巨头 AT&T 家庭光纤与宽带主网"},
    "AS701": {"kind": "isp", "tag": "🇺🇸 美国顶级光纤家宽", "brand": "Verizon Fios", "desc": "美国东海岸主力光纤入户居民宽带"},
    "AS21928": {"kind": "mobile", "tag": "🇺🇸 美国 5G 移动/无线家宽", "brand": "T-Mobile USA", "desc": "美国主流 5G 蜂窝移动网与 T-Mobile 5G Home Internet，天然 CGNAT 高信任度"},
    "AS22773": {"kind": "isp", "tag": "🇺🇸 美国大型区域家宽", "brand": "Cox Communications", "desc": "全美第三大有线居民宽带商"},
    "AS5650": {"kind": "isp", "tag": "🇺🇸 美国正规光纤家宽", "brand": "Frontier Fiber", "desc": "美国正规光纤入户宽带运营商"},
    "AS209": {"kind": "isp", "tag": "🇺🇸 美国正规居民宽带", "brand": "CenturyLink (Quantum Fiber)", "desc": "Lumen 旗下真正面向普通家庭的宽带接入网（区别于机房骨干 AS3356/AS3561）"},
    "AS6079": {"kind": "isp", "tag": "🇺🇸 美国区域有线宽带", "brand": "Astound / RCN", "desc": "美国东北与西海岸区域正规居民有线宽带"},
    "AS4713": {"kind": "isp", "tag": "🇯🇵 日本顶级原生家宽", "brand": "NTT OCN", "desc": "日本最大电信运营商 NTT 旗下主力家庭光纤宽带"},
    "AS2516": {"kind": "isp", "tag": "🇯🇵 日本头部正规家宽", "brand": "KDDI (au Hikari)", "desc": "日本第二大电信运营商 KDDI 家庭光纤与移动网"},
    "AS17676": {"kind": "isp", "tag": "🇯🇵 日本头部正规家宽", "brand": "SoftBank BB", "desc": "日本软银光宽带与家庭宽带网"},
    "AS2527": {"kind": "isp", "tag": "🇯🇵 日本高速光纤家宽", "brand": "Sony NURO 光", "desc": "索尼旗下日本高品质独享光纤家庭宽带"},
    "AS3462": {"kind": "isp", "tag": "🇹🇼 台湾中华电信家宽", "brand": "Chunghwa Telecom (HiNet)", "desc": "台湾省最大居民宽带运营商"},
    "AS4760": {"kind": "isp", "tag": "🇭🇰 香港电讯正规家宽", "brand": "HKT (Netvigator 网上行)", "desc": "香港最大入户光纤宽带运营商"},
    "AS9269": {"kind": "isp", "tag": "🇭🇰 香港宽频正规家宽", "brand": "HKBN 香港宽频", "desc": "香港主流居民光纤宽带"},
    "AS3758": {"kind": "isp", "tag": "🇸🇬 新加坡电信正规家宽", "brand": "Singtel", "desc": "新加坡最大居民光纤宽带"},
    "AS2856": {"kind": "isp", "tag": "🇬🇧 英国电信正规家宽", "brand": "BT (British Telecom)", "desc": "英国最大国家电信与居民宽带网"},
    "AS3320": {"kind": "isp", "tag": "🇩🇪 德国电信正规家宽", "brand": "Deutsche Telekom", "desc": "德国最大居民宽带运营商"},
    "AS3356": {"kind": "backbone", "tag": "🌐 国际一级骨干网 (非入户家宽)", "brand": "Lumen / Level 3", "desc": "全球 Tier-1 骨干网与政企专线，常被代理商包装为静态住宅，实非普通居民入户宽带"},
    "AS3561": {"kind": "backbone", "tag": "🏢 骨干网/企业托管 (非入户家宽)", "brand": "Savvis / Lumen", "desc": "Lumen 旗下企业托管与数据中心号段"},
    "AS174": {"kind": "backbone", "tag": "🌐 国际一级骨干网 (非入户家宽)", "brand": "Cogent Communications", "desc": "纯商业带宽批发与机房专线商，不提供居民入户宽带"},
    "AS2914": {"kind": "backbone", "tag": "🌐 国际一级骨干网 (非入户家宽)", "brand": "NTT Global IP Network", "desc": "NTT 国际商业骨干网（在海外不给普通居民拉宽带）"},
    "AS6939": {"kind": "backbone", "tag": "🏢 机房与骨干隧道商", "brand": "Hurricane Electric (HE)", "desc": "全球大型机房托管与 IPv6 隧道骨干商"},
    "AS3257": {"kind": "backbone", "tag": "🌐 国际一级骨干网", "brand": "GTT Communications", "desc": "国际一级骨干传输网，非普通居民宽带"},
    "AS9009": {"kind": "idc", "tag": "🏢 知名商业机房 / VPN 托管商", "brand": "M247", "desc": "全球大量商业 VPN 与机场落地节点常用的数据中心网络"},
    "AS20473": {"kind": "idc", "tag": "🏢 云服务器机房", "brand": "Vultr (Choopa)", "desc": "知名海外云服务器厂商 Vultr 数据中心"},
    "AS14061": {"kind": "idc", "tag": "🏢 云服务器机房", "brand": "DigitalOcean", "desc": "知名海外云服务器厂商 DigitalOcean 数据中心"},
    "AS16509": {"kind": "idc", "tag": "☁️ 公有云机房", "brand": "Amazon AWS", "desc": "亚马逊 AWS 云计算数据中心"},
    "AS15169": {"kind": "idc", "tag": "☁️ 谷歌云 / 公共基础设施", "brand": "Google LLC", "desc": "Google 公共 DNS 与 Google Cloud 云平台网络"},
    "AS13335": {"kind": "idc", "tag": "☁️ CDN 边缘 / WARP 网络", "brand": "Cloudflare", "desc": "Cloudflare 全球任播 CDN 或 WARP 出口"},
    "AS24940": {"kind": "idc", "tag": "🏢 欧洲大型机房", "brand": "Hetzner", "desc": "德国知名独立服务器与云主机机房"},
    "AS16276": {"kind": "idc", "tag": "🏢 欧洲大型机房", "brand": "OVHcloud", "desc": "法国大型服务器托管机房"},
    "AS21859": {"kind": "idc", "tag": "🏢 商业边缘机房", "brand": "Zenlayer", "desc": "常见跨国商业专线与云机房服务商"},
}


def load_history():
    if not HISTORY_FILE.exists():
        return []
    try:
        items = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        for rec in items:
            asn_s = (rec.get("profile") or {}).get("asn")
            if asn_s and not rec.get("asn_wiki") and asn_s in ASN_ENCYCLOPEDIA:
                rec["asn_wiki"] = ASN_ENCYCLOPEDIA[asn_s]
        return items
    except Exception:
        return []


def save_history(items):
    try:
        HISTORY_FILE.write_text(json.dumps(items[:30], ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def make_session(proxy_url=None):
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": UA})
    if proxy_url == "DIRECT":
        s.trust_env = False
        s.proxies = {"http": None, "https": None}
    elif proxy_url:
        s.trust_env = False
        s.proxies = {"http": proxy_url, "https": proxy_url}
    else:
        s.trust_env = True
    return s


def parse_input(mode, raw_val):
    raw_val = (raw_val or "").strip().rstrip("/")
    if mode == "current":
        return "current", None, "当前网络出口"
    if mode == "ip":
        if not raw_val:
            raise ValueError("请输入要查询的 IP 地址，例如：8.8.8.8 或 1.1.1.1")
        try:
            ip_obj = ipaddress.ip_address(raw_val)
            return "ip", str(ip_obj), f"IP 查询 ({ip_obj})"
        except Exception:
            raise ValueError("请输入合法的 IPv4 或 IPv6 地址，例如：8.8.8.8")
    if not raw_val:
        raise ValueError("请填写代理地址：http://... / socks5://... 或 IP:端口:用户名:密码")
    if "://" in raw_val:
        fixed = re.sub(r"^socks5://", "socks5h://", raw_val, flags=re.I)
        return "proxy", fixed, fixed.split("@")[-1]
    parts = raw_val.split(":")
    if len(parts) == 4:
        ip, port, user, pw = parts
        return "proxy_4", (ip, port, user, pw), f"{ip}:{port}"
    if len(parts) == 2:
        ip, port = parts
        return "proxy", f"http://{ip}:{port}", f"{ip}:{port}"
    raise ValueError("代理格式不正确，支持：http://...、socks5://...、IP:端口 或 IP:端口:用户名:密码")


def get_json(session, url, timeout=9, headers=None, verify=True):
    for attempt in range(2):
        try:
            r = session.get(url, timeout=timeout, headers=headers, verify=verify)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 404, 429):
                break
        except Exception:
            if attempt == 0:
                time.sleep(0.25)
    return None


def map_type_cn(val):
    if not val:
        return None
    v = str(val).strip().lower()
    if v in ("null", "none", "n/a", ""):
        return None
    if v in ("isp", "fixed line isp", "mobile isp", "residential", "wireless") or v.startswith("isp") or v.startswith("mob"):
        return "住宅宽带 (ISP)"
    if v in ("business", "commercial", "com", "enterprise") or v.startswith("com/"):
        return "商业宽带 (Business)"
    if v in ("hosting", "dch", "data center/web hosting/transit", "datacenter", "vpn", "compromised server") or v.startswith("dch"):
        return "机房托管 (IDC)"
    if v in ("education", "edu", "university/college/school") or v.startswith("edu"):
        return "教育网 (EDU)"
    if v in ("government", "gov") or v.startswith("gov"):
        return "政府机构 (GOV)"
    if v in ("cdn", "content delivery network", "anycast_dns"):
        return "CDN / 任播"
    if v in ("organization", "org"):
        return "组织机构 (ORG)"
    return str(val)


def bval(x):
    if isinstance(x, bool):
        return x
    if x is None:
        return None
    s = str(x).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def detect_exit_ip(session, timeout=6):
    endpoints = [
        ("https://api.ipify.org?format=json", "ip"),
        ("https://ipinfo.io/json", "ip"),
        ("https://api.ip.sb/jsonip", "ip"),
        ("https://icanhazip.com", None),
    ]
    for url, key in endpoints:
        try:
            r = session.get(url, timeout=timeout, headers=CURL_HDR)
            if r.status_code == 200:
                ip = str(r.json().get(key, "")).strip() if key else r.text.strip()
                ipaddress.ip_address(ip)
                return ip
        except Exception:
            continue
    return None


def parse_cf_trace(text):
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ==============================================================================
# 1. 全量数据源 + 原站图表专属接口并发采集
# ==============================================================================
def query_all_databases(ip, query_session, is_exit_ip=False):
    results = {}
    is_v6 = ":" in ip
    nc_hdr = {"Referer": f"https://ip.net.coffee/ip/{urllib.parse.quote(ip)}"}

    def q_nc_lookup():
        return "netcoffee_lookup", get_json(query_session, f"https://ip.net.coffee/api/ip/lookup/{urllib.parse.quote(ip)}", timeout=12, headers=nc_hdr)

    def q_nc_risk():
        return "netcoffee_risk", get_json(query_session, f"https://ip.net.coffee/api/iprisk/{urllib.parse.quote(ip)}", timeout=10, headers={"Referer": "https://ip.net.coffee/claude/"})

    def q_nc_heat():
        if is_v6:
            return "netcoffee_heat", None
        return "netcoffee_heat", get_json(query_session, f"https://ip.net.coffee/api/ipv2/heat/{urllib.parse.quote(ip)}", timeout=10, headers=nc_hdr)

    def q_nc_bgp():
        return "netcoffee_bgp", get_json(query_session, f"https://ip.net.coffee/api/ipv2/bgp/{urllib.parse.quote(ip)}", timeout=14, headers=nc_hdr)

    def q_nc_dnsbl():
        if is_v6:
            return "netcoffee_dnsbl", None
        return "netcoffee_dnsbl", get_json(query_session, f"https://ip.net.coffee/api/ipv2/dnsbl/{urllib.parse.quote(ip)}", timeout=12, headers=nc_hdr)

    def q_nc_portscan():
        return "netcoffee_portscan", get_json(query_session, f"https://ip.net.coffee/api/ip/portscan/{urllib.parse.quote(ip)}", timeout=10, headers=nc_hdr)

    def q_nc_ping():
        if is_v6:
            return "netcoffee_ping", None
        node_qs = "&".join(f"node={nid}" for nid, _, _ in GLOBAL_PING_NODES)
        u = f"https://ip.net.coffee/api/ping/global?host={urllib.parse.quote(ip)}&{node_qs}"
        d = get_json(query_session, u, timeout=8, headers=nc_hdr)
        if isinstance(d, dict) and d.get("pending") and not d.get("results"):
            time.sleep(2.0)
            d2 = get_json(query_session, u, timeout=6, headers=nc_hdr)
            if d2:
                d = d2
        return "netcoffee_ping", d

    def q_nc_related():
        return "netcoffee_related", get_json(query_session, f"https://ip.net.coffee/api/ip/related/{urllib.parse.quote(ip)}", timeout=8, headers=nc_hdr)

    def q_claude_status():
        return "claude_status", get_json(query_session, "https://ip.net.coffee/claude/status.json", timeout=6, headers={"Referer": "https://ip.net.coffee/claude/"})

    def q_ipinfo():
        return "ipinfo", get_json(query_session, f"https://ipinfo.io/widget/demo/{ip}", timeout=9, headers=CURL_HDR)

    def q_ipapico():
        return "ipapico", get_json(query_session, f"https://ipapi.co/{ip}/json/", timeout=8)

    def q_ipregistry():
        key = "sb69ksjcajfs4c"
        try:
            html = query_session.get("https://ipregistry.co", timeout=6).text
            m = re.search(r'apiKey="([a-zA-Z0-9]+)"', html)
            if m:
                key = m.group(1)
        except Exception:
            pass
        return "ipregistry", get_json(
            query_session,
            f"https://api.ipregistry.co/{ip}?hostname=true&key={key}",
            timeout=9,
            headers={"Origin": "https://ipregistry.co", "Referer": "https://ipregistry.co/"},
        )

    def q_ipquery():
        return "ipquery", get_json(query_session, f"https://api.ipquery.io/{ip}?format=json", timeout=8, headers=CURL_HDR)

    def q_proxycheck():
        return "proxycheck", get_json(query_session, f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1", timeout=8, headers=CURL_HDR)

    def q_ip_api_com():
        return "ip_api_com", get_json(
            query_session,
            f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            timeout=8,
            headers=CURL_HDR,
        )

    def q_rdap():
        d = get_json(query_session, f"https://rdap.org/ip/{ip}", timeout=9, headers=CURL_HDR)
        if not isinstance(d, dict):
            return "rdap", None
        org = ""
        abuse_emails = []
        for e in d.get("entities") or []:
            roles = e.get("roles") or []
            va = e.get("vcardArray") or []
            if len(va) > 1:
                for item in va[1]:
                    if not item:
                        continue
                    if item[0] == "fn" and ("registrant" in roles or not org):
                        val = str(item[3])
                        if not val.upper().endswith("-MNT") and not val.lower().startswith("mnt-"):
                            org = val
                    if item[0] == "email" and "abuse" in roles:
                        abuse_emails.append(str(item[3]))
            for sub in e.get("entities") or []:
                sroles = sub.get("roles") or []
                sva = sub.get("vcardArray") or []
                if len(sva) > 1:
                    for item in sva[1]:
                        if item and item[0] == "email" and "abuse" in sroles:
                            abuse_emails.append(str(item[3]))
        events = {ev.get("eventAction"): ev.get("eventDate") for ev in (d.get("events") or []) if ev.get("eventAction")}
        cidrs = []
        for c in d.get("cidr0_cidrs") or []:
            p = c.get("v4prefix") or c.get("v6prefix")
            ln = c.get("length")
            if p and ln is not None:
                cidrs.append(f"{p}/{ln}")
        return "rdap", {
            "handle": d.get("handle"),
            "name": d.get("name"),
            "type": d.get("type"),
            "country": d.get("country"),
            "startAddress": d.get("startAddress"),
            "endAddress": d.get("endAddress"),
            "cidrs": cidrs,
            "registrant": org,
            "abuse_emails": sorted(set(abuse_emails)),
            "registration_date": events.get("registration"),
            "last_changed": events.get("last changed"),
        }

    def q_ripestat():
        out = {"prefix": None, "asns": [], "rpki": None, "geo": None, "neighbours": None}
        ni = get_json(query_session, f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=8, headers=CURL_HDR)
        if isinstance(ni, dict) and isinstance(ni.get("data"), dict):
            out["prefix"] = ni["data"].get("prefix")
            out["asns"] = ni["data"].get("asns") or []
        if out["prefix"] and out["asns"]:
            asn0 = str(out["asns"][0])
            rpki = get_json(
                query_session,
                f"https://stat.ripe.net/data/rpki-validation/data.json?resource={asn0}&prefix={urllib.parse.quote(out['prefix'], safe='')}",
                timeout=8,
                headers=CURL_HDR,
            )
            if isinstance(rpki, dict) and isinstance(rpki.get("data"), dict):
                out["rpki"] = {
                    "status": rpki["data"].get("status"),
                    "validator": rpki["data"].get("validator"),
                    "roas": rpki["data"].get("validating_roas") or [],
                }
            nb = get_json(query_session, f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn0}", timeout=8, headers=CURL_HDR)
            if isinstance(nb, dict) and isinstance(nb.get("data"), dict):
                nbs = nb["data"].get("neighbours") or []
                out["neighbours"] = {
                    "counts": nb["data"].get("neighbour_counts") or {},
                    "upstreams": [f"AS{x.get('asn')}" for x in nbs if x.get("type") == "left"][:14],
                    "downstreams": [f"AS{x.get('asn')}" for x in nbs if x.get("type") == "right"][:14],
                }
        return "ripestat", out

    def q_ippure():
        return "ippure", get_json(
            query_session,
            "https://my.ippure.com/v1/info",
            timeout=9,
            headers={"Origin": "https://ippure.com", "Referer": "https://ippure.com/"},
        )

    def q_maxmind():
        d = get_json(query_session, f"https://ipinfo.check.place/{ip}?lang=cn", timeout=9, headers=CURL_HDR)
        if not d:
            d = get_json(query_session, f"https://ipinfo.check.place/{ip}?lang=en", timeout=9, headers=CURL_HDR)
        return "maxmind", d

    def q_scamalytics():
        return "scamalytics", get_json(query_session, f"https://ipinfo.check.place/{ip}?db=scamalytics", timeout=9, headers=CURL_HDR)

    def q_ipapi():
        return "ipapi", get_json(query_session, f"https://ipinfo.check.place/{ip}?db=ipapi", timeout=9, headers=CURL_HDR)

    def q_abuseipdb():
        return "abuseipdb", get_json(query_session, f"https://ipinfo.check.place/{ip}?db=abuseipdb", timeout=9, headers=CURL_HDR)

    def q_ip2location():
        return "ip2location", get_json(query_session, f"https://ipinfo.check.place/{ip}?db=ip2location", timeout=9, headers=CURL_HDR)

    def q_ipdata():
        return "ipdata", get_json(query_session, f"https://ipinfo.check.place/{ip}?db=ipdata", timeout=9, headers=CURL_HDR)

    def q_ipqs():
        d = get_json(query_session, f"https://ipinfo.check.place/{ip}?db=ipqualityscore", timeout=8, headers=CURL_HDR)
        if isinstance(d, dict) and d.get("success") is True:
            return "ipqs", d
        return "ipqs", None

    def q_dbip():
        return "dbip", get_json(query_session, f"https://api.db-ip.com/v2/free/{urllib.parse.quote(ip)}", timeout=8, headers=CURL_HDR)

    def q_dual_stack():
        out = {"ipv4": None, "ipv6": None, "prefer_version": 6 if ":" in ip else 4}
        try:
            r4 = get_json(query_session, "https://api4.ipify.org?format=json", timeout=4, headers=CURL_HDR)
            if isinstance(r4, dict) and r4.get("ip"):
                out["ipv4"] = r4["ip"]
        except Exception:
            pass
        try:
            r6 = get_json(query_session, "https://api6.ipify.org?format=json", timeout=2.5, headers=CURL_HDR)
            if isinstance(r6, dict) and r6.get("ip") and ":" in str(r6["ip"]):
                out["ipv6"] = r6["ip"]
        except Exception:
            pass
        return "dual_stack", out

    tasks = [
        q_nc_lookup, q_nc_risk, q_nc_heat, q_nc_bgp, q_nc_dnsbl,
        q_nc_portscan, q_nc_ping, q_nc_related, q_claude_status,
        q_ipinfo, q_ipapico, q_ipregistry, q_ipquery, q_proxycheck,
        q_ip_api_com, q_rdap, q_ripestat, q_dbip,
    ]
    if is_exit_ip:
        tasks.extend([q_ippure, q_maxmind, q_scamalytics, q_ipapi, q_abuseipdb, q_ip2location, q_ipdata, q_ipqs, q_dual_stack])

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(fn) for fn in tasks]
        for fut in concurrent.futures.as_completed(futs):
            try:
                k, v = fut.result()
                results[k] = v
            except Exception:
                pass

    # 第二步快查：拿到 ASN 后立即并发补齐 Radar 28 天人机流量比 & 同 ASN 机房/企业聚合
    asn_num = (
        (results.get("netcoffee_lookup") or {}).get("asn")
        or (results.get("ippure") or {}).get("asn")
        or (((results.get("ripestat") or {}).get("asns") or [None])[0])
        or str((((results.get("ipinfo") or {}).get("data") or {}).get("asn") or {}).get("asn") or "").replace("AS", "")
    )
    if asn_num:
        def q_radar():
            return "netcoffee_radar", get_json(query_session, f"https://ip.net.coffee/api/ipv2/radar/{asn_num}", timeout=8, headers=nc_hdr)

        def q_asncos():
            d = get_json(query_session, f"https://ip.net.coffee/api/ipv2/asncos/{asn_num}", timeout=8, headers=nc_hdr)
            if isinstance(d, dict) and d.get("pending"):
                time.sleep(1.5)
                d2 = get_json(query_session, f"https://ip.net.coffee/api/ipv2/asncos/{asn_num}", timeout=6, headers=nc_hdr)
                if d2:
                    d = d2
            return "netcoffee_asncos", d

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex2:
            for fut in concurrent.futures.as_completed([ex2.submit(q_radar), ex2.submit(q_asncos)]):
                try:
                    k, v = fut.result()
                    results[k] = v
                except Exception:
                    pass

    return results


# ==============================================================================
# 2. 实时出口环境（Claude 4 路 Trace + CF Meta + EDNS + 国内直连对照 + 9 项流媒体/AI）
# ==============================================================================
def query_live_environment(live_session):
    env_data = {
        "claude_traces": [],
        "outbound_matrix": [],
        "cloudflare_meta": None,
        "edns_dns": None,
        "browserleaks_dns": None,
        "tls_fp": None,
        "bilibili_zone": None,
        "ipip_zone": None,
        "direct_cn_ip": None,
        "media": [],
    }

    outbound_cf_targets = [
        ("Claude Web", "https://claude.ai/cdn-cgi/trace", "AI"),
        ("Claude Brand", "https://claude.com/cdn-cgi/trace", "AI"),
        ("Anthropic 官网", "https://www.anthropic.com/cdn-cgi/trace", "AI"),
        ("Cloudflare Edge", "https://www.cloudflare.com/cdn-cgi/trace", "Global"),
        ("ChatGPT", "https://chatgpt.com/cdn-cgi/trace", "AI"),
        ("OpenAI", "https://openai.com/cdn-cgi/trace", "AI"),
        ("Sora", "https://sora.com/cdn-cgi/trace", "AI"),
        ("Perplexity", "https://www.perplexity.ai/cdn-cgi/trace", "AI"),
        ("GitLab", "https://gitlab.com/cdn-cgi/trace", "Dev"),
        ("Node.js", "https://nodejs.org/cdn-cgi/trace", "Dev"),
        ("Coinbase", "https://www.coinbase.com/cdn-cgi/trace", "Crypto"),
        ("OKX", "https://www.okx.com/cdn-cgi/trace", "Crypto"),
    ]

    def run_trace(label, url, cat="Global"):
        t0 = time.perf_counter()
        try:
            r = live_session.get(url, timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            parsed = parse_cf_trace(r.text)
            loc = parsed.get("loc", "")
            return {
                "name": label,
                "category": cat,
                "url": url,
                "ok": r.status_code == 200 and bool(parsed.get("ip")),
                "http_status": r.status_code,
                "latency_ms": ms,
                "ip": parsed.get("ip", ""),
                "loc": loc,
                "colo": parsed.get("colo", ""),
                "http": parsed.get("http", ""),
                "tls": parsed.get("tls", ""),
                "kex": parsed.get("kex", ""),
                "sni": parsed.get("sni", ""),
                "warp": parsed.get("warp", ""),
                "gateway": parsed.get("gateway", ""),
                "claude_region_allowed": (loc not in ANTHROPIC_BLOCKED_CC) if loc else None,
            }
        except Exception as e:
            return {"name": label, "category": cat, "url": url, "ok": False, "error": str(e)[:120]}

    def q_cn_split_probes():
        cn_rows = []
        bili_data = None
        ipip_data = None
        # 1. Bilibili Zone (同时供给 IPPure 位置表 & 分流表 & 国内直连对照)
        try:
            t0 = time.perf_counter()
            rb = live_session.get("https://api.bilibili.com/x/web-interface/zone", timeout=5)
            ms = int((time.perf_counter() - t0) * 1000)
            if rb.status_code == 200:
                d = (rb.json() or {}).get("data") or {}
                if d.get("addr"):
                    bili_data = d
                    cc = "CN" if d.get("country") == "中国" else ""
                    geo_str = " ".join(x for x in [d.get("country"), d.get("province"), d.get("city"), d.get("isp")] if x)
                    cn_rows.append({"name": "Bilibili (国内分流)", "category": "China", "ok": True, "ip": d["addr"], "loc": cc, "colo": geo_str, "latency_ms": ms})
        except Exception:
            pass
        # 2. IPIP.net
        try:
            t0 = time.perf_counter()
            ri = live_session.get("https://myip.ipip.net/json", timeout=5)
            ms = int((time.perf_counter() - t0) * 1000)
            if ri.status_code == 200:
                d = (ri.json() or {}).get("data") or {}
                if d.get("ip"):
                    loc_arr = [x for x in (d.get("location") or []) if x]
                    ipip_data = {"ip": d["ip"], "location": " ".join(loc_arr), "cc": "CN" if (loc_arr and loc_arr[0] == "中国") else ""}
                    cn_rows.append({"name": "IPIP.net (国内分流)", "category": "China", "ok": True, "ip": d["ip"], "loc": ipip_data["cc"], "colo": ipip_data["location"], "latency_ms": ms})
        except Exception:
            pass
        # 3. 字节跳动边缘节点
        try:
            t0 = time.perf_counter()
            rby = live_session.head("https://perfops.byte-test.com/500b-bench.jpg", timeout=5)
            ms = int((time.perf_counter() - t0) * 1000)
            bip = rby.headers.get("x-request-ip")
            if bip:
                cn_rows.append({"name": "字节跳动 CDN", "category": "China", "ok": True, "ip": bip.strip(), "loc": "", "colo": "x-request-ip", "latency_ms": ms})
        except Exception:
            pass
        # 4. 网易云盾边缘节点
        try:
            t0 = time.perf_counter()
            rne = live_session.head("https://necaptcha.nosdn.127.net/ab7f4275c1744aa28e0a8f3a1c58c532.png", timeout=5)
            ms = int((time.perf_counter() - t0) * 1000)
            nip = rne.headers.get("cdn-user-ip")
            if nip:
                cn_rows.append({"name": "网易 CDN", "category": "China", "ok": True, "ip": nip.strip(), "loc": "", "colo": "cdn-user-ip", "latency_ms": ms})
        except Exception:
            pass
        return cn_rows, bili_data, ipip_data

    def q_cf_meta():
        return "cf_meta", get_json(
            live_session,
            "https://speed.cloudflare.com/meta",
            timeout=9,
            headers={"Referer": "https://speed.cloudflare.com/", "Origin": "https://speed.cloudflare.com"},
        )

    def q_edns():
        return "edns", get_json(live_session, "https://edns.ip-api.com/json", timeout=8)

    def q_browserleaks_dns():
        tok = uuid.uuid4().hex[:12]
        d = get_json(live_session, f"https://{tok}.dns4.browserleaks.net/", timeout=7)
        if not isinstance(d, dict):
            return None
        servers = []
        for sip, arr in d.items():
            if isinstance(arr, list) and len(arr) >= 2:
                servers.append({"ip": sip, "country_code": str(arr[0] or "").upper(), "location": arr[1], "isp": arr[2] if len(arr) > 2 else ""})
        has_cn = any(s["country_code"] == "CN" for s in servers)
        return {"servers": servers, "has_cn_leak": has_cn}

    def q_tls_fp():
        d = get_json(live_session, "https://tls.peet.ws/api/all", timeout=8)
        if not isinstance(d, dict):
            return None
        tls = d.get("tls") or {}
        h2 = d.get("http2") or {}
        return {
            "http_version": d.get("http_version"),
            "tls_version": tls.get("tls_version_negotiated"),
            "ja3": tls.get("ja3"),
            "ja3_hash": tls.get("ja3_hash"),
            "ja4": tls.get("ja4"),
            "ja4_r": tls.get("ja4_r"),
            "peetprint": tls.get("peetprint"),
            "peetprint_hash": tls.get("peetprint_hash"),
            "akamai_fingerprint": h2.get("akamai_fingerprint"),
            "akamai_hash": h2.get("akamai_fingerprint_hash"),
        }

    def q_direct_cn():
        for sess_cand in (make_session("DIRECT"), make_session(None)):
            try:
                rb = sess_cand.get("https://api.bilibili.com/x/web-interface/zone", timeout=4)
                if rb.status_code == 200:
                    bd = (rb.json() or {}).get("data") or {}
                    if bd.get("addr"):
                        loc = " ".join(x for x in [bd.get("country"), bd.get("province"), bd.get("city"), bd.get("isp")] if x)
                        return "direct_cn", {"ip": bd["addr"], "location": loc}
            except Exception:
                pass
            try:
                r = sess_cand.get("https://myip.ipip.net/json", timeout=4)
                if r.status_code == 200:
                    d = (r.json() or {}).get("data") or {}
                    if d.get("ip"):
                        return "direct_cn", {"ip": d["ip"], "location": " ".join(x for x in (d.get("location") or []) if x)}
            except Exception:
                pass
        return "direct_cn", None

    def probe_chatgpt():
        t0 = time.perf_counter()
        try:
            r1 = live_session.get(
                "https://api.openai.com/compliance/cookie_requirements",
                headers={"Authorization": "Bearer null", "Origin": "https://platform.openai.com"},
                timeout=9,
            )
            blocked = "unsupported_country" in r1.text
            if blocked:
                rc = live_session.get("https://chatgpt.com/favicon.ico", timeout=8)
                if rc.status_code != 403:
                    blocked = False
            tr = parse_cf_trace(live_session.get("https://chatgpt.com/cdn-cgi/trace", timeout=8).text)
            ms = int((time.perf_counter() - t0) * 1000)
            return {"name": "ChatGPT / OpenAI", "status": "可用" if not blocked else "地区不支持", "ok": not blocked, "region": tr.get("loc", ""), "detail": f"CF {tr.get('colo', '-')} · HTTP {r1.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "ChatGPT / OpenAI", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_claude():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://claude.ai/cdn-cgi/trace", timeout=9)
            tr = parse_cf_trace(r.text)
            loc = tr.get("loc", "")
            ok = bool(loc) and loc not in ANTHROPIC_BLOCKED_CC
            ms = int((time.perf_counter() - t0) * 1000)
            return {"name": "Claude (Anthropic)", "status": "地区支持" if ok else ("地区受限" if loc else "异常"), "ok": ok, "region": loc, "detail": f"CF {tr.get('colo', '-')} · {tr.get('tls', '-')}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Claude (Anthropic)", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_gemini():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://gemini.google.com/app", headers={"Accept-Language": "en-US,en;q=0.9"}, timeout=9, allow_redirects=True)
            ms = int((time.perf_counter() - t0) * 1000)
            blocked = ("faq" in r.url.lower() and "unavailable" in r.text.lower()) or "isn't currently supported" in r.text.lower()
            m = re.search(r'"([A-Z]{2})","[a-z]{2}-[A-Z]{2}"', r.text)
            reg = m.group(1) if m else ""
            return {"name": "Google Gemini", "status": "不可用" if blocked else "可用", "ok": not blocked and r.status_code == 200, "region": reg, "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Google Gemini", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_youtube():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.youtube.com/premium", headers={"Accept-Language": "en"}, cookies={"CONSENT": "YES+cb.20220301-11-p0.en+FX+700"}, timeout=9)
            ms = int((time.perf_counter() - t0) * 1000)
            t = r.text
            if "www.google.cn" in t:
                return {"name": "YouTube Premium", "status": "送中 (CN)", "ok": False, "region": "CN", "detail": "重定向 google.cn", "latency_ms": ms}
            mm = re.search(r'"contentRegion":"([A-Z]{2})"', t)
            reg = mm.group(1) if mm else ""
            unavail = "Premium is not available in your country" in t
            return {"name": "YouTube Premium", "status": "不支持" if unavail else "可用", "ok": not unavail and r.status_code == 200, "region": reg, "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "YouTube Premium", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_netflix():
        t0 = time.perf_counter()
        try:
            r1 = live_session.get("https://www.netflix.com/title/81280792", timeout=9)
            r2 = live_session.get("https://www.netflix.com/title/70143836", timeout=9)
            ms = int((time.perf_counter() - t0) * 1000)
            if r1.status_code == 403 and r2.status_code == 403:
                return {"name": "Netflix", "status": "屏蔽 (403)", "ok": False, "region": "", "detail": "均 403", "latency_ms": ms}
            mm = re.search(r'"id":"([A-Z]{2})","countryName"', r1.text) or re.search(r'"id":"([A-Z]{2})","countryName"', r2.text)
            reg = mm.group(1) if mm else ""
            if ("Oh no!" in r1.text or r1.status_code == 404) and ("Oh no!" in r2.text or r2.status_code == 404):
                return {"name": "Netflix", "status": "仅自制剧", "ok": False, "region": reg, "detail": "非自制受限", "latency_ms": ms}
            return {"name": "Netflix", "status": "完整解锁", "ok": True, "region": reg, "detail": f"HTTP {r1.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Netflix", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_disney():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.disneyplus.com/", timeout=9, allow_redirects=True)
            ms = int((time.perf_counter() - t0) * 1000)
            if r.status_code == 403 or "unavailable" in r.url.lower():
                return {"name": "Disney+", "status": "不可用", "ok": False, "region": "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
            m = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', r.text) or re.search(r'/([a-z]{2}-[a-z]{2})/', r.url)
            reg = m.group(1).split("-")[-1].upper() if m else ""
            return {"name": "Disney+", "status": "可访问", "ok": r.status_code == 200, "region": reg, "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Disney+", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_tiktok():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.tiktok.com/", timeout=9)
            ms = int((time.perf_counter() - t0) * 1000)
            mm = re.search(r'"region":"([A-Z]{2})"', r.text)
            return {"name": "TikTok", "status": "可用" if (mm or r.status_code == 200) else f"HTTP {r.status_code}", "ok": bool(mm or r.status_code == 200), "region": mm.group(1) if mm else "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "TikTok", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_amazon():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.primevideo.com", timeout=9)
            ms = int((time.perf_counter() - t0) * 1000)
            mm = re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', r.text)
            return {"name": "Amazon Prime Video", "status": "可用" if mm else f"HTTP {r.status_code}", "ok": bool(mm), "region": mm.group(1) if mm else "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Amazon Prime Video", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_reddit():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.reddit.com/svc/shreddit/reddit-chat", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            if r.status_code == 200:
                mm = re.search(r'country="([A-Z]{2})"', r.text)
                return {"name": "Reddit", "status": "可访问", "ok": True, "region": mm.group(1) if mm else "", "detail": "HTTP 200", "latency_ms": ms}
            return {"name": "Reddit", "status": f"受限 ({r.status_code})", "ok": False, "region": "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Reddit", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_github():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://github.com/manifest.json", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code == 200
            return {"name": "GitHub / Copilot", "status": "直连正常" if ok else f"HTTP {r.status_code}", "ok": ok, "region": "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "GitHub / Copilot", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_amazon_shop():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.amazon.com/favicon.ico", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code in (200, 301, 302)
            return {"name": "Amazon 跨境电商", "status": "正常访问" if ok else f"风控 ({r.status_code})", "ok": ok, "region": "US", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Amazon 跨境电商", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_temu():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://www.temu.com/favicon.ico", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code in (200, 301, 302)
            return {"name": "Temu 跨境平台", "status": "正常访问" if ok else f"HTTP {r.status_code}", "ok": ok, "region": "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Temu 跨境平台", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_steam():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://store.steampowered.com/favicon.ico", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code == 200
            return {"name": "Steam 商店", "status": "正常访问" if ok else f"HTTP {r.status_code}", "ok": ok, "region": "", "detail": f"HTTP {r.status_code}", "latency_ms": ms}
        except Exception as e:
            return {"name": "Steam 商店", "status": "连接失败", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    def probe_stripe():
        t0 = time.perf_counter()
        try:
            r = live_session.get("https://js.stripe.com/v3/", timeout=8)
            ms = int((time.perf_counter() - t0) * 1000)
            ok = r.status_code == 200 and len(r.text) > 5000
            return {"name": "Stripe 支付", "status": "直连正常" if ok else f"异常 ({r.status_code})", "ok": ok, "region": "", "detail": f"HTTP {r.status_code} · {len(r.text)//1024}KB", "latency_ms": ms}
        except Exception as e:
            return {"name": "Stripe 支付", "status": "被阻断 / 超时", "ok": False, "region": "", "detail": str(e)[:80], "latency_ms": None}

    media_probes = [
        probe_chatgpt, probe_claude, probe_gemini, probe_youtube, probe_netflix,
        probe_disney, probe_tiktok, probe_amazon, probe_reddit, probe_github,
        probe_amazon_shop, probe_temu, probe_steam, probe_stripe,
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        trace_futs = [ex.submit(run_trace, lbl, u, cat) for lbl, u, cat in outbound_cf_targets]
        cn_split_fut = ex.submit(q_cn_split_probes)
        meta_fut = ex.submit(q_cf_meta)
        edns_fut = ex.submit(q_edns)
        bldon_fut = ex.submit(q_browserleaks_dns)
        tls_fut = ex.submit(q_tls_fp)
        direct_fut = ex.submit(q_direct_cn)
        media_futs = [ex.submit(fn) for fn in media_probes]

        all_cf_traces = [f.result() for f in trace_futs]
        cn_rows, bili_data, ipip_data = cn_split_fut.result()
        env_data["claude_traces"] = all_cf_traces[:4]
        env_data["outbound_matrix"] = cn_rows + all_cf_traces
        env_data["bilibili_zone"] = bili_data
        env_data["ipip_zone"] = ipip_data
        env_data["cloudflare_meta"] = meta_fut.result()[1]
        env_data["edns_dns"] = edns_fut.result()[1]
        env_data["browserleaks_dns"] = bldon_fut.result()
        env_data["tls_fp"] = tls_fut.result()
        env_data["direct_cn_ip"] = direct_fut.result()[1]
        env_data["media"] = [f.result() for f in media_futs]
    return env_data


# ==============================================================================
# 3. 30 库 DoH DNSBL（识别 Spamhaus PBL 127.0.0.10/11 家宽策略豁免）
# ==============================================================================
def query_dnsbl_detailed(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            return {"supported": False, "note": "DNSBL 列表仅适用于 IPv4 地址", "total": 0, "clean": 0, "marked": 0, "blacklisted": 0, "items": []}
    except Exception:
        return {"supported": False, "note": "无效 IP", "total": 0, "clean": 0, "marked": 0, "blacklisted": 0, "items": []}

    rev = ".".join(reversed(ip.split(".")))
    direct_sess = make_session("DIRECT")

    def check_one(zone_tuple):
        zone, engine, cat = zone_tuple
        qname = f"{rev}.{zone}"
        t0 = time.perf_counter()
        for base in ("https://223.5.5.5/resolve", "https://223.6.6.6/resolve"):
            try:
                r = direct_sess.get(base, params={"name": qname, "type": "A"}, timeout=3.5, verify=False)
                ms = int((time.perf_counter() - t0) * 1000)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("Status") == 0 and isinstance(d.get("Answer"), list):
                        ans = [str(x.get("data", "")) for x in d["Answer"] if x.get("type") == 1]
                        real_ans = [a for a in ans if not a.startswith("127.255.255.")]
                        if not real_ans:
                            return {"zone": zone, "engine": engine, "category": cat, "status": "clean", "records": [], "ms": ms}
                        if "spamhaus" in zone:
                            non_pbl = [a for a in real_ans if a not in ("127.0.0.10", "127.0.0.11")]
                            if not non_pbl:
                                return {"zone": zone, "engine": engine, "category": cat, "status": "pbl_clean", "records": real_ans, "ms": ms}
                            real_ans = non_pbl
                        if any(a in ("127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.9") for a in real_ans):
                            return {"zone": zone, "engine": engine, "category": cat, "status": "blacklisted", "records": real_ans, "ms": ms}
                        return {"zone": zone, "engine": engine, "category": cat, "status": "marked", "records": real_ans, "ms": ms}
                    return {"zone": zone, "engine": engine, "category": cat, "status": "clean", "records": [], "ms": ms}
            except Exception:
                continue
        return {"zone": zone, "engine": engine, "category": cat, "status": "timeout", "records": [], "ms": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        items = list(ex.map(check_one, DNSBL_ZONES))

    clean_cnt = sum(1 for x in items if x["status"] in ("clean", "pbl_clean"))
    marked_cnt = sum(1 for x in items if x["status"] == "marked")
    black_cnt = sum(1 for x in items if x["status"] == "blacklisted")
    timeout_cnt = sum(1 for x in items if x["status"] == "timeout")
    return {
        "supported": True,
        "total": len(items),
        "clean": clean_cnt,
        "marked": marked_cnt,
        "blacklisted": black_cnt,
        "timeout": timeout_cnt,
        "items": items,
    }


# ==============================================================================
# 4. Cloudflare Speedtest 完整多梯度测速（含延迟采样、抖动、4档下载、3档上传）
# ==============================================================================
def run_cloudflare_speedtest(session, progress_cb=None):
    hdr = {"Referer": "https://speed.cloudflare.com/", "Origin": "https://speed.cloudflare.com"}
    if progress_cb:
        progress_cb(8, "正在连接 speed.cloudflare.com 获取边缘接入机房...")
    meta = get_json(session, "https://speed.cloudflare.com/meta", timeout=10, headers=hdr)
    if not meta:
        raise RuntimeError("无法连接 speed.cloudflare.com/meta")

    def sample_loaded_rtt(count=3):
        vals = []
        for k in range(count):
            try:
                t0 = time.perf_counter()
                rr = session.get(f"https://speed.cloudflare.com/__down?bytes=0&loadProbe={k}", timeout=6, headers=hdr)
                if rr.status_code == 200:
                    vals.append(round((time.perf_counter() - t0) * 1000, 1))
            except Exception:
                pass
        return round(statistics.median(vals), 1) if vals else None

    if progress_cb:
        progress_cb(20, "正在采样 10 次空载延迟、抖动与丢包率 (Unloaded Latency / Jitter / Loss)...")
    rtts = []
    attempted_pings = 10
    for i in range(attempted_pings + 1):
        try:
            t0 = time.perf_counter()
            r = session.get(f"https://speed.cloudflare.com/__down?bytes=0&measId={i}", timeout=6, headers=hdr)
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code == 200 and i > 0:
                rtts.append(round(dt, 1))
        except Exception:
            pass
    loss_pct = round(max(0, attempted_pings - len(rtts)) / attempted_pings * 100, 1)
    if not rtts:
        rtts = [0.0]
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    jitter = round(statistics.mean(diffs), 1) if diffs else 0.0
    sorted_rtts = sorted(rtts)
    p25 = sorted_rtts[min(len(sorted_rtts) - 1, int(len(sorted_rtts) * 0.25))]
    p75 = sorted_rtts[min(len(sorted_rtts) - 1, int(len(sorted_rtts) * 0.75))]
    p90 = sorted_rtts[min(len(sorted_rtts) - 1, int(len(sorted_rtts) * 0.9))]
    latency = {
        "samples_ms": rtts,
        "min_ms": round(min(rtts), 1),
        "p25_ms": round(p25, 1),
        "avg_ms": round(statistics.mean(rtts), 1),
        "p50_ms": round(statistics.median(rtts), 1),
        "p75_ms": round(p75, 1),
        "p90_ms": round(p90, 1),
        "max_ms": round(max(rtts), 1),
        "jitter_ms": jitter,
        "packet_loss_pct": loss_pct,
        "download_loaded_ms": None,
        "upload_loaded_ms": None,
    }

    dl_steps = []
    dl_plan = [("100 KB", 100_000), ("1 MB", 1_000_000), ("5 MB", 5_000_000), ("10 MB", 10_000_000)]
    for idx, (label, nbytes) in enumerate(dl_plan):
        if progress_cb:
            progress_cb(32 + idx * 12, f"正在测试下载带宽与负载延迟（{label}）...")
        try:
            if nbytes == 5_000_000:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as lpool:
                    f_rtt = lpool.submit(sample_loaded_rtt, 3)
                    t0 = time.perf_counter()
                    r = session.get(f"https://speed.cloudflare.com/__down?bytes={nbytes}", timeout=25, headers=hdr)
                    dt = max(0.001, time.perf_counter() - t0)
                    latency["download_loaded_ms"] = f_rtt.result()
            else:
                t0 = time.perf_counter()
                r = session.get(f"https://speed.cloudflare.com/__down?bytes={nbytes}", timeout=25, headers=hdr)
                dt = max(0.001, time.perf_counter() - t0)
            got = len(r.content)
            mbps = round((got * 8) / dt / 1_000_000, 2)
            dl_steps.append({"size": label, "bytes": got, "elapsed_s": round(dt, 2), "mbps": mbps})
        except Exception as e:
            dl_steps.append({"size": label, "bytes": 0, "elapsed_s": 0, "mbps": None, "error": str(e)[:80]})

    valid_dl = [x["mbps"] for x in dl_steps if x["mbps"] is not None]
    download_mbps = round(max(valid_dl), 2) if valid_dl else None
    download_avg = round(statistics.mean(valid_dl), 2) if valid_dl else None

    ul_steps = []
    ul_plan = [("256 KB", 256_000), ("1 MB", 1_000_000), ("2 MB", 2_000_000)]
    for idx, (label, nbytes) in enumerate(ul_plan):
        if progress_cb:
            progress_cb(80 + idx * 6, f"正在测试上传带宽与负载延迟（{label}）...")
        try:
            payload = b"0" * nbytes
            if nbytes == 2_000_000:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as lpool:
                    f_rtt = lpool.submit(sample_loaded_rtt, 3)
                    t0 = time.perf_counter()
                    r = session.post("https://speed.cloudflare.com/__up", data=payload, timeout=25, headers=hdr)
                    dt = max(0.001, time.perf_counter() - t0)
                    latency["upload_loaded_ms"] = f_rtt.result()
            else:
                t0 = time.perf_counter()
                r = session.post("https://speed.cloudflare.com/__up", data=payload, timeout=25, headers=hdr)
                dt = max(0.001, time.perf_counter() - t0)
            if r.status_code == 200:
                mbps = round((nbytes * 8) / dt / 1_000_000, 2)
                ul_steps.append({"size": label, "bytes": nbytes, "elapsed_s": round(dt, 2), "mbps": mbps})
            else:
                ul_steps.append({"size": label, "bytes": 0, "elapsed_s": round(dt, 2), "mbps": None, "error": f"HTTP {r.status_code}"})
        except Exception as e:
            ul_steps.append({"size": label, "bytes": 0, "elapsed_s": 0, "mbps": None, "error": str(e)[:80]})

    valid_ul = [x["mbps"] for x in ul_steps if x["mbps"] is not None]
    upload_mbps = round(max(valid_ul), 2) if valid_ul else None
    upload_avg = round(statistics.mean(valid_ul), 2) if valid_ul else None

    return {
        "tested_at": datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
        "meta": meta,
        "latency": latency,
        "download_peak_mbps": download_mbps,
        "download_avg_mbps": download_avg,
        "download_steps": dl_steps,
        "upload_peak_mbps": upload_mbps,
        "upload_avg_mbps": upload_avg,
        "upload_steps": ul_steps,
    }


def compute_subnet_details(ip_str, cidr_str, rdap_obj):
    out = {
        "ip_decimal": None,
        "cidr": cidr_str or "",
        "netmask": "",
        "wildcard": "",
        "network_addr": "",
        "broadcast_addr": "",
        "first_usable": "",
        "last_usable": "",
        "usable_hosts": None,
        "rdap_range": f"{rdap_obj.get('startAddress')} - {rdap_obj.get('endAddress')}" if rdap_obj.get("startAddress") and rdap_obj.get("endAddress") else "",
    }
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        out["ip_decimal"] = str(int(ip_obj))
        target_cidr = cidr_str or (rdap_obj.get("cidrs") or [None])[0] or (f"{ip_str}/24" if ip_obj.version == 4 else f"{ip_str}/64")
        net = ipaddress.ip_network(target_cidr, strict=False)
        out["cidr"] = str(net)
        out["network_addr"] = str(net.network_address)
        if net.version == 4:
            out["netmask"] = str(net.netmask)
            out["wildcard"] = str(net.hostmask)
            out["broadcast_addr"] = str(net.broadcast_address)
            if net.num_addresses > 2:
                out["first_usable"] = str(net.network_address + 1)
                out["last_usable"] = str(net.broadcast_address - 1)
                out["usable_hosts"] = net.num_addresses - 2
            else:
                out["usable_hosts"] = net.num_addresses
        else:
            out["usable_hosts"] = net.num_addresses
    except Exception:
        pass
    return out


# ==============================================================================
# 5. 报告整合（保留全部原站图表所需完整结构体）
# ==============================================================================
def build_full_report(ip, mode, label, is_exit_ip, dbs, live_env, dnsbl, speedtest=None):
    ipp = dbs.get("ippure") or {}
    nc = dbs.get("netcoffee_lookup") or {}
    nc_risk = dbs.get("netcoffee_risk") or {}
    nc_heat = dbs.get("netcoffee_heat")
    nc_bgp = dbs.get("netcoffee_bgp")
    nc_dnsbl = dbs.get("netcoffee_dnsbl")
    nc_radar = dbs.get("netcoffee_radar")
    nc_asncos = dbs.get("netcoffee_asncos")
    nc_portscan = dbs.get("netcoffee_portscan")
    nc_ping = dbs.get("netcoffee_ping")
    nc_related = dbs.get("netcoffee_related")
    claude_status = dbs.get("claude_status")
    mm = dbs.get("maxmind") or {}
    ii = (dbs.get("ipinfo") or {}).get("data") or {}
    ipapico = dbs.get("ipapico") or {}
    sc = dbs.get("scamalytics") or {}
    ir = dbs.get("ipregistry") or {}
    ia = dbs.get("ipapi") or {}
    ab = (dbs.get("abuseipdb") or {}).get("data") or {}
    i2 = dbs.get("ip2location") or {}
    id_ = dbs.get("ipdata") or {}
    iq = dbs.get("ipquery") or {}
    pc = (dbs.get("proxycheck") or {}).get(ip) or {}
    ipapi_com = dbs.get("ip_api_com") or {}
    dbip = dbs.get("dbip") or {}
    dual_stack = dbs.get("dual_stack") or {}
    rdap = dbs.get("rdap") or {}
    ripe = dbs.get("ripestat") or {}

    iq_isp = iq.get("isp") or {}
    iq_loc = iq.get("location") or {}
    iq_risk = iq.get("risk") or {}
    sc_main = sc.get("scamalytics") or {}
    sc_ext = sc.get("external_datasources") or {}
    sc_px = sc_main.get("scamalytics_proxy") or {}
    ir_sec = ir.get("security") or {}
    ir_loc = ir.get("location") or {}
    ii_priv = ii.get("privacy") or {}
    i2_px = i2.get("proxy") or {}
    id_th = id_.get("threat") or {}

    asn_num = (
        (mm.get("ASN") or {}).get("AutonomousSystemNumber")
        or ipp.get("asn")
        or nc.get("asn")
        or (ripe.get("asns") or [None])[0]
        or str((ii.get("asn") or {}).get("asn") or "").replace("AS", "")
        or str(iq_isp.get("asn") or "").replace("AS", "")
        or str(pc.get("asn") or "").replace("AS", "")
        or (re.search(r"AS(\d+)", str(ipapi_com.get("as") or "")).group(1) if re.search(r"AS(\d+)", str(ipapi_com.get("as") or "")) else "")
    )
    asn_str = f"AS{asn_num}" if asn_num else "-"
    org_str = (
        (mm.get("ASN") or {}).get("AutonomousSystemOrganization")
        or nc.get("asOrganization")
        or (ii.get("asn") or {}).get("name")
        or iq_isp.get("org")
        or ipapi_com.get("org")
        or ipapi_com.get("isp")
        or ipp.get("asOrganization")
        or "-"
    )
    as_domain = (
        (ii.get("asn") or {}).get("domain")
        or (ii.get("company") or {}).get("domain")
        or (ia.get("asn") or {}).get("domain")
        or (ia.get("company") or {}).get("domain")
        or nc.get("company_domain")
        or (ir.get("connection") or {}).get("domain")
        or (id_.get("asn") or {}).get("domain")
        or ""
    )
    country_code = (
        ipp.get("countryCode")
        or (nc.get("countryCode") or "").upper()
        or (mm.get("Country") or {}).get("IsoCode")
        or ii.get("country")
        or ipapi_com.get("countryCode")
        or dbip.get("countryCode")
        or iq_loc.get("country_code")
        or ""
    ).upper()
    country_name = ipp.get("country") or ipapi_com.get("country") or dbip.get("countryName") or nc.get("country") or (mm.get("Country") or {}).get("Name") or ""
    region_name = ipp.get("region") or ipapi_com.get("regionName") or dbip.get("stateProv") or ii.get("region") or ipapico.get("region") or iq_loc.get("state") or pc.get("region") or ""
    city_name = ipp.get("city") or ipapi_com.get("city") or dbip.get("city") or ii.get("city") or ipapico.get("city") or iq_loc.get("city") or pc.get("city") or ""
    timezone_str = ipp.get("timezone") or ipapi_com.get("timezone") or ii.get("timezone") or nc_risk.get("timezone") or ((mm.get("City") or {}).get("Location") or {}).get("TimeZone") or iq_loc.get("timezone") or ""
    postal = ipp.get("postalCode") or ipapi_com.get("zip") or ii.get("postal") or ipapico.get("postal") or pc.get("postcode") or ""

    # 优选高精度经纬度用于地图绘制
    lat, lon = None, None
    for cand_lat, cand_lon in [
        (ipp.get("latitude"), ipp.get("longitude")),
        (ipapi_com.get("lat"), ipapi_com.get("lon")),
        (iq_loc.get("latitude"), iq_loc.get("longitude")),
        (ir_loc.get("latitude"), ir_loc.get("longitude")),
        (ipapico.get("latitude"), ipapico.get("longitude")),
        (((mm.get("City") or {}).get("Location") or {}).get("Latitude"), ((mm.get("City") or {}).get("Location") or {}).get("Longitude")),
    ]:
        try:
            if cand_lat is not None and cand_lon is not None:
                lat, lon = float(cand_lat), float(cand_lon)
                break
        except Exception:
            continue
    if lat is None and nc.get("geo_sources"):
        for gs in nc["geo_sources"]:
            if gs.get("lat") is not None and gs.get("lon") is not None:
                lat, lon = float(gs["lat"]), float(gs["lon"])
                break

    rdns = nc.get("rdns") or nc_risk.get("rdns") or ipapi_com.get("reverse") or ii.get("hostname") or ""
    reg_cc = (
        (nc.get("registered_country_code") or "").upper()
        or ((mm.get("Country") or {}).get("RegisteredCountry") or {}).get("IsoCode")
        or (rdap.get("country") or "").upper()
        or ""
    )
    is_broadcast = ipp.get("isBroadcast")
    if is_broadcast is None and reg_cc and country_code:
        is_broadcast = (reg_cc != country_code)

    subnet_calc = compute_subnet_details(ip, nc.get("cidr") or ripe.get("prefix"), rdap)

    # IPPure 主页卡片 1:1 复刻所需的 6+ 源位置行 (Cloudflare / IP2Location / DB-IP / MaxMind / IPInfo.io / ipapi.co / Bilibili / IPIP)
    cf_m = (live_env or {}).get("cloudflare_meta") or {}
    bili_z = (live_env or {}).get("bilibili_zone") or {}
    ipip_z = (live_env or {}).get("ipip_zone") or {}
    ippure_geo_rows = []
    if cf_m.get("country"):
        ippure_geo_rows.append({"source": "Cloudflare", "cc": cf_m.get("country"), "text": ", ".join(x for x in [cf_m.get("country"), cf_m.get("region"), cf_m.get("city")] if x)})
    if i2.get("country_code"):
        ippure_geo_rows.append({"source": "IP2Location", "cc": i2.get("country_code"), "text": ", ".join(x for x in [i2.get("country_name"), i2.get("region_name"), i2.get("city_name")] if x)})
    if dbip.get("countryCode"):
        ippure_geo_rows.append({"source": "DB-IP", "cc": dbip.get("countryCode"), "text": ", ".join(x for x in [dbip.get("countryName"), dbip.get("stateProv"), dbip.get("city")] if x)})
    mm_cc = (mm.get("Country") or {}).get("IsoCode") or ((sc_ext.get("maxmind_geolite2") or {}).get("ip_country_code"))
    if mm_cc:
        mm_sub = (((mm.get("Subdivisions") or [{}])[0]).get("Name") if mm.get("Subdivisions") else None) or (sc_ext.get("maxmind_geolite2") or {}).get("ip_state_name")
        mm_city = (mm.get("City") or {}).get("Name") or (sc_ext.get("maxmind_geolite2") or {}).get("ip_city")
        ippure_geo_rows.append({"source": "MaxMind", "cc": mm_cc, "text": ", ".join(x for x in [(mm.get("Country") or {}).get("Name") or mm_cc, mm_sub, mm_city] if x)})
    if ii.get("country"):
        ippure_geo_rows.append({"source": "IPInfo.io", "cc": ii.get("country"), "text": ", ".join(x for x in [ii.get("country"), ii.get("region"), ii.get("city")] if x)})
    if ipapico.get("country_code") and not ipapico.get("error"):
        ippure_geo_rows.append({"source": "IPapi.co", "cc": ipapico.get("country_code"), "text": ", ".join(x for x in [ipapico.get("country_name"), ipapico.get("region"), ipapico.get("city")] if x)})
    if bili_z.get("addr"):
        b_cc = "CN" if bili_z.get("country") == "中国" else country_code
        b_note = "" if bili_z.get("addr") == ip else f" (分流出口 {bili_z.get('addr')})"
        ippure_geo_rows.append({"source": "Bilibili", "cc": b_cc, "text": ", ".join(x for x in [bili_z.get("country"), bili_z.get("province"), bili_z.get("city"), bili_z.get("isp")] if x) + b_note})
    if ipip_z.get("ip"):
        i_note = "" if ipip_z.get("ip") == ip else f" (分流出口 {ipip_z.get('ip')})"
        ippure_geo_rows.append({"source": "IPIP.net", "cc": ipip_z.get("cc") or country_code, "text": (ipip_z.get("location") or "") + i_note})

    # 多源位置与归属对比总表
    geo_table = []

    def add_geo(src, cc, reg, city, tz, coords, isp_org, usage_t, comp_t, risk_raw):
        if any(x is not None and x != "" for x in (cc, reg, city, isp_org, usage_t, comp_t, risk_raw)):
            geo_table.append({
                "source": src,
                "country": str(cc or "").upper() or "—",
                "region": reg or "—",
                "city": city or "—",
                "timezone": tz or "—",
                "coords": coords or "—",
                "isp_org": isp_org or "—",
                "usage_type": usage_t or "—",
                "company_type": comp_t or "—",
                "native_risk": risk_raw if (risk_raw is not None and risk_raw != "") else "—",
            })

    if cf_m.get("country"):
        add_geo("Cloudflare", cf_m.get("country"), cf_m.get("region"), cf_m.get("city"), cf_m.get("timezone"),
                f"{cf_m.get('latitude')}, {cf_m.get('longitude')}" if cf_m.get("latitude") else None,
                f"AS{cf_m.get('asn')} {cf_m.get('asOrganization') or ''}".strip(), None, None, f"边缘机房 {cf_m.get('colo') or '-'}")
    if ipp:
        add_geo("IPPure", ipp.get("countryCode"), ipp.get("region"), ipp.get("city"), ipp.get("timezone"),
                f"{ipp.get('latitude')}, {ipp.get('longitude')}" if ipp.get("latitude") else None,
                f"AS{ipp.get('asn')} {ipp.get('asOrganization') or ''}".strip(),
                "住宅宽带 (ISP)" if ipp.get("isResidential") is True else ("非住宅" if ipp.get("isResidential") is False else None),
                "原生 IP" if ipp.get("isBroadcast") is False else ("广播 IP" if ipp.get("isBroadcast") is True else None),
                f"IPPure系数: {ipp.get('fraudScore')}%")
    if dbip.get("countryCode"):
        add_geo("DB-IP", dbip.get("countryCode"), dbip.get("stateProv"), dbip.get("city"), None, None, None, None, None, None)
    if nc:
        add_geo("Net.Coffee", nc.get("countryCode"), nc.get("region"), nc.get("city"), nc_risk.get("timezone"), None,
                f"AS{nc.get('asn')} {nc.get('asOrganization') or ''} ({nc.get('isp') or ''})".strip(),
                "住宅宽带 (ISP)" if nc.get("isResidential") is True else ("机房托管 (IDC)" if nc.get("is_datacenter") else map_type_cn(nc.get("asn_kind"))),
                map_type_cn(nc.get("company_type")),
                f"可信度 {nc.get('trust_score')} · 滥用 {nc.get('abuser_score') or '-'}")
    if ii:
        add_geo("IPinfo.io", ii.get("country"), ii.get("region"), ii.get("city"), ii.get("timezone"), ii.get("loc"),
                f"{(ii.get('asn') or {}).get('asn') or ''} {(ii.get('asn') or {}).get('name') or ''}".strip(),
                map_type_cn((ii.get("asn") or {}).get("type")), map_type_cn((ii.get("company") or {}).get("type")), None)
    if ipapico and not ipapico.get("error"):
        add_geo("ipapi.co", ipapico.get("country_code"), ipapico.get("region"), ipapico.get("city"), ipapico.get("timezone"),
                f"{ipapico.get('latitude')}, {ipapico.get('longitude')}" if ipapico.get("latitude") else None,
                f"{ipapico.get('asn') or ''} {ipapico.get('org') or ''}".strip(), None, None, None)
    if ir:
        add_geo("ipregistry", (ir_loc.get("country") or {}).get("code"), (ir_loc.get("region") or {}).get("name"), ir_loc.get("city"),
                (ir.get("time_zone") or {}).get("id"),
                f"{ir_loc.get('latitude')}, {ir_loc.get('longitude')}" if ir_loc.get("latitude") else None,
                f"AS{(ir.get('connection') or {}).get('asn') or ''} {(ir.get('connection') or {}).get('organization') or ''}".strip(),
                map_type_cn((ir.get("connection") or {}).get("type")), map_type_cn((ir.get("company") or {}).get("type")), None)
    if ia:
        ia_loc = ia.get("location") or {}
        add_geo("ipapi.is", ia_loc.get("country_code"), ia_loc.get("state"), ia_loc.get("city"), ia_loc.get("timezone"),
                f"{ia_loc.get('latitude')}, {ia_loc.get('longitude')}" if ia_loc.get("latitude") else None,
                f"AS{(ia.get('asn') or {}).get('asn') or ''} {(ia.get('asn') or {}).get('org') or ''}".strip(),
                map_type_cn((ia.get("asn") or {}).get("type")), map_type_cn((ia.get("company") or {}).get("type")),
                (ia.get("company") or {}).get("abuser_score"))
    if i2:
        add_geo("IP2Location", i2.get("country_code"), i2.get("region_name"), i2.get("city_name"),
                (i2.get("time_zone_info") or {}).get("olson") or i2.get("time_zone"),
                f"{i2.get('latitude')}, {i2.get('longitude')}" if i2.get("latitude") else None,
                f"AS{i2.get('asn') or ''} {i2.get('as') or ''}".strip(),
                map_type_cn(str(i2.get("usage_type") or "").split("/")[0]),
                map_type_cn(str((i2.get("as_info") or {}).get("as_usage_type") or "").split("/")[0]),
                f"fraud_score: {i2.get('fraud_score')}/100")
    if sc:
        mm_g = sc_ext.get("maxmind_geolite2") or {}
        add_geo("Scamalytics", mm_g.get("ip_country_code"), mm_g.get("ip_state_name"), mm_g.get("ip_city"), mm_g.get("ip_time_zone"),
                mm_g.get("ip_geolocation"), f"AS{mm_g.get('asn') or ''} {mm_g.get('as_name') or ''}".strip(),
                "机房托管 (IDC)" if sc_px.get("is_datacenter") else None, None,
                f"{sc_main.get('scamalytics_score')}/100 ({sc_main.get('scamalytics_risk') or '-'})")
    if ab:
        add_geo("AbuseIPDB", ab.get("countryCode"), None, None, None, None, ab.get("isp"),
                map_type_cn(ab.get("usageType")), None, f"{ab.get('abuseConfidenceScore')}% ({ab.get('totalReports', 0)}次举报)")
    if id_:
        add_geo("ipdata.co", id_.get("country_code"), id_.get("region"), id_.get("city"), (id_.get("time_zone") or {}).get("name"),
                f"{id_.get('latitude')}, {id_.get('longitude')}" if id_.get("latitude") else None,
                f"{(id_.get('asn') or {}).get('asn') or ''} {(id_.get('asn') or {}).get('name') or ''}".strip(),
                map_type_cn((id_.get("asn") or {}).get("type")), None, None)
    if iq:
        add_geo("ipquery.io", iq_loc.get("country_code"), iq_loc.get("state"), iq_loc.get("city"), iq_loc.get("timezone"),
                f"{iq_loc.get('latitude')}, {iq_loc.get('longitude')}" if iq_loc.get("latitude") else None,
                f"{iq_isp.get('asn') or ''} {iq_isp.get('org') or ''}".strip(),
                "机房托管 (IDC)" if iq_risk.get("is_datacenter") else None, None, f"risk: {iq_risk.get('risk_score')}/100")
    if pc:
        add_geo("ProxyCheck", pc.get("isocode"), pc.get("region"), pc.get("city"), pc.get("timezone"),
                f"{pc.get('latitude')}, {pc.get('longitude')}" if pc.get("latitude") else None,
                f"{pc.get('asn') or ''} {pc.get('provider') or ''}".strip(),
                map_type_cn(pc.get("type")), None, f"risk: {pc.get('risk')}/100")
    if ipapi_com and ipapi_com.get("status") == "success":
        add_geo("ip-api.com", ipapi_com.get("countryCode"), ipapi_com.get("regionName"), ipapi_com.get("city"), ipapi_com.get("timezone"),
                f"{ipapi_com.get('lat')}, {ipapi_com.get('lon')}" if ipapi_com.get("lat") is not None else None,
                f"{ipapi_com.get('as') or ''} / {ipapi_com.get('isp') or ''}".strip(" /"),
                "机房托管 (IDC)" if ipapi_com.get("hosting") else None, None,
                f"proxy={ipapi_com.get('proxy')}, hosting={ipapi_com.get('hosting')}")

    # 10 库 × 9 因子风控矩阵
    factor_matrix = []

    def add_frow(db, cc, proxy, vpn, server, tor, abuser, bot, mobile, anycast_relay):
        if any(x is not None for x in (cc, proxy, vpn, server, tor, abuser, bot, mobile, anycast_relay)):
            factor_matrix.append({
                "db": db,
                "country": str(cc).upper() if cc else None,
                "proxy": bval(proxy),
                "vpn": bval(vpn),
                "server": bval(server),
                "tor": bval(tor),
                "abuser": bval(abuser),
                "bot": bval(bot),
                "mobile": bval(mobile),
                "relay_anycast": bval(anycast_relay),
            })

    add_frow("IPinfo", ii.get("country"), ii_priv.get("proxy"), ii_priv.get("vpn"), ii_priv.get("hosting"), ii_priv.get("tor"), None, None, None, ii_priv.get("relay") or ii.get("anycast"))
    add_frow("ipregistry", (ir_loc.get("country") or {}).get("code"), ir_sec.get("is_proxy"), ir_sec.get("is_vpn"), ir_sec.get("is_cloud_provider"), ir_sec.get("is_tor") or ir_sec.get("is_tor_exit"), ir_sec.get("is_abuser") or ir_sec.get("is_threat"), None, None, ir_sec.get("is_relay") or ir_sec.get("is_anonymous"))
    add_frow("ipapi.is", (ia.get("location") or {}).get("country_code"), ia.get("is_proxy"), ia.get("is_vpn"), ia.get("is_datacenter"), ia.get("is_tor"), ia.get("is_abuser"), ia.get("is_crawler"), ia.get("is_mobile"), ia.get("is_anycast") or ia.get("is_bogon"))
    add_frow("IP2Location", i2.get("country_code"), i2.get("is_proxy") or i2_px.get("is_public_proxy") or i2_px.get("is_web_proxy") or i2_px.get("is_residential_proxy"), i2_px.get("is_vpn"), i2_px.get("is_data_center"), i2_px.get("is_tor"), i2_px.get("is_spammer"), i2_px.get("is_web_crawler") or i2_px.get("is_scanner") or i2_px.get("is_botnet"), None, i2_px.get("is_consumer_privacy_network"))
    add_frow("Scamalytics", (sc_ext.get("maxmind_geolite2") or {}).get("ip_country_code"), (sc_ext.get("firehol") or {}).get("is_proxy"), sc_px.get("is_vpn"), sc_px.get("is_datacenter"), (sc_ext.get("x4bnet") or {}).get("is_tor"), sc_main.get("is_blacklisted_external"), (sc_ext.get("x4bnet") or {}).get("is_blacklisted_spambot"), None, sc_px.get("is_apple_icloud_private_relay"))
    add_frow("ipdata", id_.get("country_code"), id_th.get("is_proxy"), None, id_th.get("is_datacenter"), id_th.get("is_tor"), id_th.get("is_threat") or id_th.get("is_known_abuser") or id_th.get("is_known_attacker"), None, None, id_th.get("is_icloud_relay") or id_th.get("is_bogon"))
    add_frow("Net.Coffee", nc.get("countryCode"), nc.get("is_proxy"), nc.get("is_vpn"), nc.get("is_datacenter"), nc.get("is_tor"), nc.get("is_abuser"), nc.get("is_crawler"), nc.get("is_mobile"), nc.get("is_bogon"))
    add_frow("ipquery", iq_loc.get("country_code"), iq_risk.get("is_proxy"), iq_risk.get("is_vpn"), iq_risk.get("is_datacenter"), iq_risk.get("is_tor"), None, None, iq_risk.get("is_mobile"), None)
    add_frow("ProxyCheck", pc.get("isocode"), pc.get("proxy"), True if str(pc.get("type") or "").lower() == "vpn" else False if pc else None, True if str(pc.get("type") or "").lower() == "hosting" else False if pc else None, None, None, None, None, None)
    if ipapi_com and ipapi_com.get("status") == "success":
        add_frow("ip-api.com", ipapi_com.get("countryCode"), ipapi_com.get("proxy"), None, ipapi_com.get("hosting"), None, None, None, ipapi_com.get("mobile"), None)
    ipqs = dbs.get("ipqs") or {}
    if ipqs and ipqs.get("success") is True:
        add_frow("IPQS", ipqs.get("country_code"), ipqs.get("proxy"), ipqs.get("vpn"), None, ipqs.get("tor"), ipqs.get("recent_abuse"), ipqs.get("bot_status"), ipqs.get("mobile"), None)

    # 第三方原生色阶数值（供前端渲染 IPPure ColorMap 色阶尺）
    risk_gauges = [
        {"name": "IPPure 纯净度系数", "source": "ippure.com", "val": ipp.get("fraudScore") if ipp else None, "invert": False, "note": "0-25%极纯 · <40%正常 · >50%偏脏"},
        {"name": "Scamalytics 欺诈指数", "source": "scamalytics.com", "val": sc_main.get("scamalytics_score"), "invert": False, "note": "<20低危 · 20-60中危 · >60高危"},
        {"name": "IP2Location 风险指数", "source": "ip2location.com", "val": i2.get("fraud_score"), "invert": False, "note": "<33低危 · 33-66中危 · >66高危"},
        {"name": "AbuseIPDB 举报置信度", "source": "abuseipdb.com", "val": ab.get("abuseConfidenceScore"), "invert": False, "note": f"累计黑客/滥用举报 {ab.get('totalReports', 0)} 次" if ab else "0%代表零举报"},
        {"name": "ProxyCheck 风险值", "source": "proxycheck.io", "val": pc.get("risk"), "invert": False, "note": f"识别类型: {pc.get('type') or '-'}"},
        {"name": "ipquery 威胁分", "source": "ipquery.io", "val": iq_risk.get("risk_score"), "invert": False, "note": "0-100 越低越安全"},
    ]
    if ipqs and ipqs.get("fraud_score") is not None:
        risk_gauges.append({"name": "IPQS 欺诈分", "source": "ipqualityscore.com", "val": ipqs.get("fraud_score"), "invert": False, "note": "<75正常 · >=85高危"})

    hit_proxy = sum(1 for r in factor_matrix if r["proxy"] is True)
    hit_vpn = sum(1 for r in factor_matrix if r["vpn"] is True)
    hit_dc = sum(1 for r in factor_matrix if r["server"] is True)
    asn_wiki = ASN_ENCYCLOPEDIA.get(asn_str)

    return {
        "ip": ip,
        "mode": mode,
        "label": label,
        "is_exit_ip": is_exit_ip,
        "checked_at": datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
        "asn_wiki": asn_wiki,
        "profile": {
            "asn": asn_str,
            "asn_num": asn_num,
            "org": org_str,
            "as_domain": as_domain,
            "isp": nc.get("isp") or ipapi_com.get("isp") or ipp.get("asOrganization") or "-",
            "country_code": country_code,
            "country_name": country_name,
            "region": region_name,
            "city": city_name,
            "postal": postal,
            "timezone": timezone_str,
            "lat": lat,
            "lon": lon,
            "rdns": rdns,
            "registered_country": reg_cc,
            "registered_country_name": nc.get("registered_country") or "",
            "is_broadcast": is_broadcast,
            "is_residential": ipp.get("isResidential") if ipp else nc.get("isResidential"),
        },
        "dual_stack": dual_stack or None,
        "subnet_calc": subnet_calc,
        "ippure_geo_rows": ippure_geo_rows,
        "ippure": ipp or None,
        "netcoffee": {
            "lookup": nc or None,
            "risk": nc_risk or None,
            "heat": nc_heat or None,
            "bgp": nc_bgp or None,
            "dnsbl": nc_dnsbl or None,
            "radar": nc_radar or None,
            "asncos": nc_asncos or None,
            "portscan": nc_portscan or None,
            "ping": nc_ping or None,
            "related": nc_related or None,
            "claude_status": claude_status or None,
        },
        "bgp_rdap": {
            "ripestat": ripe or None,
            "rdap": rdap or None,
        },
        "live_env": live_env,
        "risk_gauges": risk_gauges,
        "geo_table": geo_table,
        "factor_matrix": factor_matrix,
        "dnsbl": dnsbl,
        "speedtest": speedtest,
        "brief": {
            "country_city": f"{country_code or '-'} · {region_name} {city_name}".strip(),
            "asn": asn_str,
            "org": org_str,
            "nc_trust": nc.get("trust_score"),
            "ippure_fraud": ipp.get("fraudScore") if ipp else None,
            "scam_score": sc_main.get("scamalytics_score"),
            "hit_proxy": hit_proxy,
            "hit_vpn": hit_vpn,
            "hit_dc": hit_dc,
            "bl_black": dnsbl.get("blacklisted", 0),
            "bl_total": dnsbl.get("total", 0),
        },
        "raw_sources": dbs,
    }


def run_scan_job(job_id, mode, raw_val, include_speedtest=False):
    try:
        kind, parsed, label = parse_input(mode, raw_val)
    except Exception as e:
        JOBS[job_id].update({"status": "error", "error": str(e)})
        return

    try:
        live_sess = None
        query_sess = make_session(None)
        ip = None
        is_exit_ip = False

        if kind == "ip":
            ip = parsed
            JOBS[job_id].update({"stage": f"已锁定 IP {ip}，正在核验是否为当前出口...", "percent": 10})
            cur_ip = detect_exit_ip(query_sess, timeout=3)
            if cur_ip and cur_ip == ip:
                is_exit_ip = True
                live_sess = query_sess
                label = f"IP 查询 ({ip} · 匹配当前出口，已自动启用全量探测)"
        elif kind == "proxy_4":
            w_ip, w_port, w_user, w_pw = parsed
            q_user = urllib.parse.quote(w_user, safe="")
            q_pw = urllib.parse.quote(w_pw, safe="")
            JOBS[job_id].update({"stage": f"正在连接代理 {w_ip}:{w_port}...", "percent": 10})
            for scheme in ("http", "socks5h"):
                s_try = make_session(f"{scheme}://{q_user}:{q_pw}@{w_ip}:{w_port}")
                found = detect_exit_ip(s_try, timeout=8)
                if found:
                    live_sess = s_try
                    ip = found
                    is_exit_ip = True
                    break
            if not ip:
                raise RuntimeError(f"无法连通代理 {w_ip}:{w_port}，请核对地址与认证信息")
        elif kind == "proxy":
            JOBS[job_id].update({"stage": f"正在连接代理 {label}...", "percent": 10})
            live_sess = make_session(parsed)
            ip = detect_exit_ip(live_sess, timeout=8)
            if not ip:
                raise RuntimeError(f"无法连通代理 {label}")
            is_exit_ip = True
        else:
            JOBS[job_id].update({"stage": "正在识别当前网络出口 IP...", "percent": 10})
            live_sess = make_session(None)
            ip = detect_exit_ip(live_sess, timeout=8)
            if not ip:
                raise RuntimeError("未能获取当前公网 IP")
            is_exit_ip = True

        JOBS[job_id].update({
            "stage": f"正在并发采集 {ip} 全量图表与数据（BGP 拓扑 / 网段热度 / 人机比例 / 全球延迟 / 端口 / 15+ 风险库）...",
            "percent": 32,
        })

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f_dbs = pool.submit(query_all_databases, ip, live_sess or query_sess, is_exit_ip)
            f_bl = pool.submit(query_dnsbl_detailed, ip)
            dbs = f_dbs.result()
            dnsbl = f_bl.result()

        live_env = None
        if is_exit_ip and live_sess is not None:
            JOBS[job_id].update({"stage": "正在实测 16 站点分流出口、DNS 泄露、JA4 指纹与 14 项流媒体/AI 服务...", "percent": 55})
            live_env = query_live_environment(live_sess)

        speedtest = None
        if include_speedtest and (live_sess is not None or kind == "current"):
            def sp_cb(pct, msg):
                JOBS[job_id].update({"stage": msg, "percent": 72 + int(pct * 0.26)})
            try:
                speedtest = run_cloudflare_speedtest(live_sess or query_sess, progress_cb=sp_cb)
            except Exception as se:
                speedtest = {"error": str(se)}

        report = build_full_report(ip, mode, label, is_exit_ip, dbs, live_env, dnsbl, speedtest=speedtest)
        report["id"] = job_id

        with LOCK:
            hist = load_history()
            hist = [report] + [h for h in hist if h.get("id") != job_id]
            save_history(hist)

        JOBS[job_id].update({"status": "done", "percent": 100, "stage": "检测完成", "report": report})
    except Exception as e:
        JOBS[job_id].update({"status": "error", "error": f"检测失败：{e}"})


def run_speedtest_job(job_id, raw_proxy):
    try:
        raw_proxy = (raw_proxy or "").strip()
        if raw_proxy:
            kind, parsed, _ = parse_input("proxy", raw_proxy)
            if kind == "proxy_4":
                w_ip, w_port, w_user, w_pw = parsed
                sess = make_session(f"http://{urllib.parse.quote(w_user, safe='')}:{urllib.parse.quote(w_pw, safe='')}@{w_ip}:{w_port}")
            else:
                sess = make_session(parsed)
        else:
            sess = make_session(None)

        def cb(pct, msg):
            JOBS[job_id].update({"stage": msg, "percent": pct})

        res = run_cloudflare_speedtest(sess, progress_cb=cb)
        JOBS[job_id].update({"status": "done", "percent": 100, "stage": "Cloudflare 测速完成", "report": res})
    except Exception as e:
        JOBS[job_id].update({"status": "error", "error": f"测速失败：{e}"})


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            body = INDEX_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/land110.txt":
            body = LAND_FILE.read_bytes() if LAND_FILE.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/history":
            self._send_json({"items": load_history()})
            return
        if path.startswith("/api/job/"):
            jid = path.split("/")[-1]
            job = JOBS.get(jid)
            self._send_json(job if job else {"error": "not found"}, 200 if job else 404)
            return
        if path.startswith("/api/portscan/"):
            target_ip = urllib.parse.unquote(path.split("/api/portscan/", 1)[1])
            s = make_session(None)
            d = get_json(s, f"https://ip.net.coffee/api/ip/portscan/{urllib.parse.quote(target_ip)}?force=1", timeout=12, headers={"Referer": f"https://ip.net.coffee/ip/{target_ip}"})
            self._send_json(d or {"ok": False})
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore") if length else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}
        if path == "/api/scan":
            mode = payload.get("mode", "current")
            raw_val = payload.get("value", "")
            inc_sp = bool(payload.get("include_speedtest", False))
            jid = uuid.uuid4().hex[:10]
            JOBS[jid] = {"id": jid, "status": "running", "percent": 5, "stage": "正在启动并发引擎...", "report": None, "error": None}
            threading.Thread(target=run_scan_job, args=(jid, mode, raw_val, inc_sp), daemon=True).start()
            self._send_json({"job_id": jid})
            return
        if path == "/api/speedtest":
            raw_proxy = payload.get("proxy", "")
            jid = uuid.uuid4().hex[:10]
            JOBS[jid] = {"id": jid, "status": "running", "percent": 5, "stage": "正在初始化 Cloudflare 测速...", "report": None, "error": None}
            threading.Thread(target=run_speedtest_job, args=(jid, raw_proxy), daemon=True).start()
            self._send_json({"job_id": jid})
            return
        self.send_error(404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/history/"):
            rid = path.split("/")[-1]
            with LOCK:
                save_history([h for h in load_history() if h.get("id") != rid])
            self._send_json({"ok": True})
            return
        self.send_error(404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def find_free_port(preferred=18668):
    for p in [preferred] + list(range(preferred + 1, preferred + 50)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):
        if _stream and hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(errors="replace")
            except Exception:
                pass
    if os.name == "nt":
        os.system("title 双螺旋究极缝合测ip（ip好纯我好爱）")
    preferred_port = 18668
    if "--port" in sys.argv:
        try:
            preferred_port = int(sys.argv[sys.argv.index("--port") + 1])
        except Exception:
            pass
    port = find_free_port(preferred_port)
    url = f"http://127.0.0.1:{port}"
    srv = ThreadedHTTPServer(("127.0.0.1", port), Handler)
    print("============================================================")
    print("   双螺旋究极缝合测ip（ip好纯我好爱） 已启动！")
    print(f"   浏览器访问地址：{url}")
    print("   提示：使用期间请勿关闭此黑框窗口；关闭窗口即退出程序。")
    print("============================================================", flush=True)
    if "--no-browser" not in sys.argv:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
