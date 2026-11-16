"""
위협 정보 연동

- 국가·통신사(ASN): DB-IP Lite(CC BY 4.0) MMDB 파일을 서버에 두고 오프라인으로 조회한다. 외부 전송 없음.
- 검색봇 진위 확인: 역방향 DNS → 정방향 DNS 재확인 (각 검색엔진이 공식 안내하는 방식)
- AbuseIPDB 평판 조회: 사용자가 동의했을 때만, 탐지된 IP만 전송한다.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from functools import lru_cache
from pathlib import Path

from .analyzer import finalize

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

COUNTRY_KO = {
    "KR": "대한민국", "US": "미국", "CN": "중국", "JP": "일본", "RU": "러시아", "DE": "독일", "NL": "네덜란드",
    "GB": "영국", "FR": "프랑스", "SG": "싱가포르", "HK": "홍콩", "TW": "대만", "VN": "베트남", "IN": "인도",
    "BR": "브라질", "CA": "캐나다", "AU": "호주", "ID": "인도네시아", "TH": "태국", "UA": "우크라이나",
    "IR": "이란", "TR": "튀르키예", "PL": "폴란드", "RO": "루마니아", "SE": "스웨덴", "FI": "핀란드",
    "IT": "이탈리아", "ES": "스페인", "BG": "불가리아", "LT": "리투아니아", "SC": "세이셸", "PH": "필리핀",
    "MY": "말레이시아", "BD": "방글라데시", "PK": "파키스탄", "MX": "멕시코", "AR": "아르헨티나", "ZA": "남아공",
}
HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode", "akamai",
    "vultr", "choopa", "oracle", "contabo", "alibaba", "tencent", "huawei cloud", "leaseweb", "m247",
    "scaleway", "online s.a.s", "datacamp", "hostinger", "ionos", "cloudflare", "fastly", "naver cloud",
    "kt cloud", "gabia", "cafe24", "hosting", "server", "data center", "datacenter", "vps",
)

# 역방향 DNS가 이 도메인으로 끝나야 진짜 봇 (각 사 공식 안내 기준)
BOT_DOMAINS = {
    "googlebot": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "bingbot": (".search.msn.com",),
    "yeti": (".naver.com",),
    "applebot": (".applebot.apple.com",),
    "yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
}


# ── 국가·ASN ────────────────────────────────────────────────
class GeoLookup:
    def __init__(self, country_db: str | None = None, asn_db: str | None = None):
        self.country = self._open(country_db or os.getenv("GEOIP_COUNTRY_DB") or DATA_DIR / "dbip-country.mmdb")
        self.asn = self._open(asn_db or os.getenv("GEOIP_ASN_DB") or DATA_DIR / "dbip-asn.mmdb")

    @staticmethod
    def _open(path):
        try:
            import maxminddb
            return maxminddb.open_database(str(path)) if Path(path).exists() else None
        except Exception:
            return None

    @property
    def available(self) -> bool:
        return bool(self.country or self.asn)

    def lookup(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if not addr.is_global:
            return {"scope": "사설·예약 대역", "country": "", "country_name": "예약·사설 IP", "asn": None, "org": ""}
        out = {"scope": "", "country": "", "country_name": "", "asn": None, "org": ""}
        if self.country:
            rec = self.country.get(ip) or {}
            code = rec.get("country_code") or (rec.get("country") or {}).get("iso_code") or ""
            out["country"] = code
            out["country_name"] = COUNTRY_KO.get(code, code)
        if self.asn:
            rec = self.asn.get(ip) or {}
            out["asn"] = rec.get("autonomous_system_number")
            out["org"] = rec.get("autonomous_system_organization") or ""
            low = out["org"].lower()
            if any(k in low for k in HOSTING_KEYWORDS):
                out["scope"] = "데이터센터·클라우드"
        return out


@lru_cache(maxsize=1)
def default_geo() -> GeoLookup:
    return GeoLookup()


# ── 검색봇 진위 ─────────────────────────────────────────────
def _resolve(ip: str, domains: tuple[str, ...]) -> bool:
    host = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    if not host.endswith(domains):
        return False
    return ip in socket.gethostbyname_ex(host)[2] or ip in {
        a[4][0] for a in socket.getaddrinfo(host, None)}


_dns_state = {"ok": None, "checked": 0.0}


def dns_available(ttl: float = 600) -> bool:
    """역방향 DNS가 실제로 동작하는 서버인지 확인한다. (DNS가 안 되는 환경에서 진짜 봇을 사칭으로 오판하지 않도록)"""
    now = time.time()
    if _dns_state["ok"] is None or now - _dns_state["checked"] > ttl:
        ex = ThreadPoolExecutor(max_workers=1)
        try:
            host = ex.submit(socket.gethostbyaddr, "8.8.8.8").result(timeout=3)[0]
            _dns_state["ok"] = host.lower().rstrip(".").endswith("dns.google")
        except Exception:
            _dns_state["ok"] = False
        finally:
            ex.shutdown(wait=False)
        _dns_state["checked"] = now
    return bool(_dns_state["ok"])


def verify_bot(ip: str, agent: str, timeout: float = 2.0) -> bool | None:
    """진짜 봇이면 True, 사칭이면 False, 확인할 수 없으면 None."""
    low = agent.lower()
    domains = next((v for k, v in BOT_DOMAINS.items() if k in low), None)
    if not domains or not dns_available():
        return None
    ex = ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(_resolve, ip, domains)
    try:
        return fut.result(timeout=timeout)
    except socket.herror:
        return False          # PTR 레코드 자체가 없음 → 진짜 봇이 아님
    except Exception:
        return None           # DNS 장애·시간 초과 → 판단 보류
    finally:
        ex.shutdown(wait=False)


# ── AbuseIPDB ───────────────────────────────────────────────
def abuse_check(ip: str, key: str, timeout: float = 4.0) -> dict | None:
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?{q}",
                                 headers={"Key": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            data = json.load(res).get("data", {})
    except Exception:
        return None
    return {
        "score": int(data.get("abuseConfidenceScore") or 0),
        "reports": int(data.get("totalReports") or 0),
        "last": data.get("lastReportedAt") or "",
        "usage": data.get("usageType") or "",
        "isp": data.get("isp") or "",
    }


# ── 보고서에 덧붙이기 ─────────────────────────────────────────
def enrich(result: dict, geo: GeoLookup | None = None, abuse_key: str | None = None,
           abuse_max: int = 20, abuse_fn=abuse_check) -> dict:
    geo = geo or default_geo()
    info = {"geo": geo.available, "abuse": False, "abuse_checked": 0}

    if geo.available:
        countries: dict[str, int] = {}
        orgs: dict[str, int] = {}
        for ip in result["ips"]:
            g = geo.lookup(ip["ip"])
            ip["intel"]["geo"] = g
            label = g.get("country_name") or "알 수 없음"
            countries[label] = countries.get(label, 0) + 1
            if g.get("org"):
                orgs[g["org"]] = orgs.get(g["org"], 0) + 1
        info["countries"] = sorted(countries.items(), key=lambda x: -x[1])[:10]
        info["orgs"] = sorted(orgs.items(), key=lambda x: -x[1])[:10]

    if abuse_key:
        targets = [ip for ip in result["ips"] if _is_public(ip["ip"])][:abuse_max]
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(abuse_fn, ip["ip"], abuse_key): ip for ip in targets}
            wait(futs, timeout=15)
        for fut, ip in futs.items():
            res = fut.result() if fut.done() and not fut.exception() else None
            if not res:
                continue
            ip["intel"]["abuse"] = res
            info["abuse_checked"] += 1
            if res["score"] >= 50:
                lvl = "높음" if res["score"] >= 80 else "중간"
                ip["findings"].append({
                    "rule": "TI", "name": "알려진 악성 IP", "level": lvl,
                    "reason": f"AbuseIPDB 신고 신뢰도 {res['score']}% · 최근 90일 신고 {res['reports']:,}건",
                    "action": "여러 사이트에서 공격으로 신고된 IP입니다. 방화벽이나 WAF에서 차단을 우선 검토하세요.",
                    "start": "", "end": ""})
        info["abuse"] = info["abuse_checked"] > 0
        info["abuse_failed"] = len(targets) - info["abuse_checked"]
        finalize(result)

    result["intel"] = info
    return result


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
