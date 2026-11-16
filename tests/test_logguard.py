import csv
import gzip
import io
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config
from app.engine.analyzer import analyze
from app.engine.parser import LogFormatError, LogTooLargeError, parse_path, parse_stream

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "app" / "sample" / "sample_access.log"
LABELS = ROOT / "tests" / "sample_labels.csv"

COMBINED = '203.0.113.5 - - [16/Nov/2026:21:52:48 +0900] "GET /index.html HTTP/1.1" 200 3460 "-" "Mozilla/5.0"\n'
COMMON = '203.0.113.5 - - [16/Nov/2026:21:52:48 +0900] "GET /index.html HTTP/1.1" 200 3460\n'
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"


def line(ip, t, url, status=200, ua=UA):
    ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "GET {url} HTTP/1.1" {status} 512 "-" "{ua}"\n'


# ── 파서 ─────────────────────────────────────────────
def test_combined_and_common():
    p = parse_stream(io.BytesIO(COMBINED.encode() * 3), 10**7, 10**6)
    assert p.fmt == "combined" and p.parsed == 3
    q = parse_stream(io.BytesIO(COMMON.encode() * 3), 10**7, 10**6)
    assert q.fmt == "common" and q.parsed == 3 and q.warnings


def test_gzip_upload():
    data = gzip.compress(SAMPLE.read_bytes())
    p = parse_stream(io.BytesIO(data), 10**8, 10**7)
    assert p.parsed == parse_path(str(SAMPLE)).parsed


def test_not_a_log():
    with pytest.raises(LogFormatError):
        parse_stream(io.BytesIO(b"hello\nworld\n"), 10**7, 10**6)


def test_gzip_bomb_is_stopped():
    bomb = gzip.compress(COMBINED.encode() * 200_000)   # 약 20MB로 풀림
    with pytest.raises(LogTooLargeError):
        parse_stream(io.BytesIO(bomb), max_bytes=1024 * 1024, max_lines=10**8)


# ── 탐지 ─────────────────────────────────────────────
def test_sample_all_attacks_found_no_false_positive():
    p = parse_path(str(SAMPLE))
    r = analyze(p.df, p.fmt)
    labels = {row["ip"]: row["label"] for row in csv.DictReader(open(LABELS, encoding="utf-8"))}
    found = {ip["ip"] for ip in r["ips"]}
    attacks = {ip for ip, lb in labels.items() if lb == "attack"}
    assert attacks <= found
    assert not (found - attacks)


def test_normal_traffic_has_few_false_positives():
    """정상 사용자만 300명 있는 로그에서 오탐률이 낮아야 한다."""
    rng = random.Random(1)
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    pages = ["/", "/about", "/blog/1", "/blog/2", "/css/app.css", "/js/app.js", "/login", "/img/a.png"]
    out = []
    for i in range(300):
        ip = f"198.51.{i // 250}.{i % 250 + 1}"
        for _ in range(rng.randint(3, 60)):
            t = t0 + timedelta(seconds=rng.uniform(0, 86400))
            url = rng.choice(pages)
            status = 404 if rng.random() < 0.03 else 200
            out.append(line(ip, t, url, status))
    out.append(line("66.249.66.1", t0, "/", ua="Googlebot/2.1"))
    p = parse_stream(io.BytesIO("".join(out).encode()), 10**8, 10**7)
    r = analyze(p.df, p.fmt)
    high = [x for x in r["ips"] if x["level"] == "높음"]
    assert not high
    assert len(r["ips"]) / r["summary"]["ips"] < 0.05


def test_rules_on_crafted_attacks():
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rows = [line(f"198.51.100.{i}", t0 + timedelta(seconds=i * 30), "/") for i in range(1, 15)]
    rows += [line("203.0.113.9", t0 + timedelta(seconds=k * 0.2), f"/wp-login.php?pw={k}") for k in range(40)]
    rows += [line("203.0.113.10", t0, "/.env", 404, ua="nuclei")]
    p = parse_stream(io.BytesIO("".join(rows).encode()), 10**8, 10**7)
    r = {x["ip"]: {f["rule"] for f in x["findings"]} for x in analyze(p.df, p.fmt)["ips"]}
    assert "R6" in r["203.0.113.9"]
    assert {"R3", "R4"} <= r["203.0.113.10"]


# ── 웹 ───────────────────────────────────────────────
@pytest.fixture()
def client(monkeypatch):
    from app import main
    main._hits.clear()
    return TestClient(main.app)


def test_pages(client):
    assert client.get("/").status_code == 200
    assert client.get("/sample").status_code == 200
    assert client.get("/privacy").status_code == 200
    res = client.get("/")
    assert "script-src 'self'" in res.headers["content-security-policy"]
    assert res.headers["x-frame-options"] == "DENY"


def test_xss_in_log_is_escaped(client):
    evil = '203.0.113.66 - - [16/Nov/2026:21:52:48 +0900] "GET /a?<script>alert(1)</script> HTTP/1.1" 404 1 "-" "<img src=x onerror=alert(2)>"\n'
    body = (COMBINED * 5 + evil * 3).encode()
    res = client.post("/analyze", files={"file": ("access.log", body)})
    assert res.status_code == 200
    assert "<script>alert(1)</script>" not in res.text
    assert "<img src=x" not in res.text
    assert "&lt;script&gt;" in res.text or "\\u003cscript\\u003e" in res.text


def test_bad_file_shows_error(client):
    res = client.post("/analyze", files={"file": ("a.txt", b"not a log")})
    assert res.status_code == 400
    assert "인식되지 않습니다" in res.text


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_COUNT", 2)
    for _ in range(2):
        assert client.post("/api/analyze", files={"file": ("a.log", COMBINED.encode())}).status_code == 200
    assert client.post("/api/analyze", files={"file": ("a.log", COMBINED.encode())}).status_code == 429


def test_upload_too_large(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_MB", 0)
    res = client.post("/api/analyze", files={"file": ("a.log", COMBINED.encode() * 10)})
    assert res.status_code == 413


# ── v2: 시간 구간·실제 IP·사용자 지정 형식·위협 정보 ───────────────
def _normal_background(rng, t0, n=60):
    out = []
    pages = ["/", "/about", "/blog/1", "/blog/2", "/css/app.css", "/login"]
    for i in range(n):
        ip = f"198.51.100.{i + 1}"
        for _ in range(rng.randint(5, 40)):
            out.append(line(ip, t0 + timedelta(seconds=rng.uniform(0, 86400)), rng.choice(pages)))
    return out


def test_session_level_ai_finds_attack_hidden_in_normal_ip():
    """하루 종일 정상적으로 쓰던 IP가 한 시간대에만 조용히 스캔하면 그 구간을 잡아내야 한다."""
    rng = random.Random(3)
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rows = _normal_background(rng, t0)
    sneaky = "203.0.113.77"
    for h in range(0, 24, 2):                                   # 평소: 2시간마다 정상 방문
        for k in range(6):
            rows.append(line(sneaky, t0 + timedelta(hours=h, seconds=k * 20), rng.choice(["/", "/blog/1"])))
    scan_at = t0 + timedelta(hours=13, minutes=5)
    for k, path in enumerate(["/old/", "/test/", "/tmp.html", "/v1/", "/api/users", "/dev/", "/upload/", "/private/"]):
        rows.append(line(sneaky, scan_at + timedelta(seconds=k * 25), path, 404))
    p = parse_stream(io.BytesIO("".join(rows).encode()), 10**8, 10**7)
    r = {x["ip"]: x for x in analyze(p.df, p.fmt, display_tz="UTC")["ips"]}
    assert sneaky in r
    ai = [f for f in r[sneaky]["findings"] if f["rule"] == "AI"][0]
    assert ai["start"].startswith("2026-11-01T13:0")
    assert "구간" in ai["reason"]


def test_xff_real_ip_is_used():
    t = "16/Nov/2026:21:52:48 +0900"
    body = "".join(f'10.0.0.1 - - [{t}] "GET /x HTTP/1.1" 200 1 "-" "M" "203.0.113.{i % 5}, 10.0.0.1"\n' for i in range(50))
    p = parse_stream(io.BytesIO(body.encode()), 10**7, 10**6)
    assert p.fmt == "nginx_xff" and p.ip_source == "xff"
    assert set(p.df["ip"]) == {f"203.0.113.{i}" for i in range(5)}
    q = parse_stream(io.BytesIO(body.encode()), 10**7, 10**6, ip_source="remote")
    assert set(q.df["ip"]) == {"10.0.0.1"}


def test_custom_formats():
    apache = '%v %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i" %D'
    l1 = 'site.kr 203.0.113.9 - - [16/Nov/2026:21:52:48 +0900] "GET /a HTTP/2.0" 200 5 "-" "sqlmap/1.8" 1234\n'
    p = parse_stream(io.BytesIO(l1.encode() * 3), 10**7, 10**6, log_format=apache)
    assert p.fmt == "custom" and p.df.iloc[0]["agent"] == "sqlmap/1.8"
    nginx = '$remote_addr [$time_iso8601] "$request" $status $body_bytes_sent $request_time "$http_user_agent"'
    l2 = '203.0.113.8 [2026-11-16T21:52:48+09:00] "GET /b?q=1 HTTP/1.1" 404 0 0.002 "Mozilla"\n'
    q = parse_stream(io.BytesIO(l2.encode() * 3), 10**7, 10**6, log_format=nginx)
    assert q.df.iloc[0]["url"] == "/b?q=1" and str(q.df.iloc[0]["time"]) == "2026-11-16 12:52:48+00:00"
    with pytest.raises(LogFormatError):
        parse_stream(io.BytesIO(l2.encode() * 3), 10**7, 10**6, log_format=apache)


def test_fake_search_bot_is_flagged():
    rng = random.Random(4)
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rows = _normal_background(rng, t0)
    for ip in ("66.249.66.1", "203.0.113.200"):
        for k in range(200):
            rows.append(line(ip, t0 + timedelta(seconds=k * 0.2), f"/blog/{k}", ua="Mozilla/5.0 (compatible; Googlebot/2.1)"))
    p = parse_stream(io.BytesIO("".join(rows).encode()), 10**8, 10**7)
    verifier = lambda ip, ua: ip == "66.249.66.1"          # noqa: E731
    r = {x["ip"]: x for x in analyze(p.df, p.fmt, bot_verifier=verifier)["ips"]}
    assert "66.249.66.1" not in r                            # 진짜 봇은 과도한 요청 예외
    names = {f["name"] for f in r["203.0.113.200"]["findings"]}
    assert {"검색봇 사칭", "과도한 요청"} <= names


def test_geo_and_abuse_enrichment():
    from app.engine.intel import GeoLookup, enrich
    t = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rows = [line("8.8.8.8", t + timedelta(seconds=k * 0.1), "/.env", 404, ua="nuclei") for k in range(30)]
    rows += [line(f"198.51.100.{i}", t, "/") for i in range(1, 12)]
    p = parse_stream(io.BytesIO("".join(rows).encode()), 10**8, 10**7)
    r = analyze(p.df, p.fmt)
    fake_abuse = lambda ip, key: {"score": 97, "reports": 321, "last": "", "usage": "Data Center", "isp": "x"}  # noqa: E731
    enrich(r, geo=GeoLookup(), abuse_key="test", abuse_fn=fake_abuse)
    ip = r["ips"][0]
    assert ip["intel"]["geo"]["country"] == "US" and ip["intel"]["geo"]["asn"] == 15169
    assert ip["intel"]["abuse"]["score"] == 97
    assert any(f["rule"] == "TI" and f["level"] == "높음" for f in ip["findings"])
    assert r["intel"]["countries"][0][0] == "미국"


def test_report_has_no_inline_styles_or_scripts(client):
    html = client.get("/sample").text
    assert ' style="' not in html                            # CSP style-src 'self' 와 충돌 방지
    import re as _re
    inline = [m for m in _re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", html) if "application/json" not in m]
    assert not inline


def test_verify_bot_dns_logic(monkeypatch):
    import socket
    from app.engine import intel
    ptr = {"66.249.66.1": "crawl-66-249-66-1.googlebot.com", "203.0.113.5": "evil.example.net"}
    fwd = {"crawl-66-249-66-1.googlebot.com": "66.249.66.1"}

    def gethostbyaddr(ip):
        if ip not in ptr:
            raise socket.herror("no ptr")
        return ptr[ip], [], [ip]

    monkeypatch.setattr(intel, "dns_available", lambda: True)
    monkeypatch.setattr(intel.socket, "gethostbyaddr", gethostbyaddr)
    monkeypatch.setattr(intel.socket, "gethostbyname_ex", lambda h: (h, [], [fwd.get(h, "0.0.0.0")]))
    monkeypatch.setattr(intel.socket, "getaddrinfo", lambda h, p: [])
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1)"
    assert intel.verify_bot("66.249.66.1", ua) is True
    assert intel.verify_bot("203.0.113.5", ua) is False      # 도메인 불일치
    assert intel.verify_bot("203.0.113.6", ua) is False      # PTR 없음
    assert intel.verify_bot("203.0.113.6", "Mozilla/5.0 Chrome") is None


def test_bot_check_skipped_when_dns_broken(monkeypatch):
    from app.engine import intel
    monkeypatch.setattr(intel, "dns_available", lambda: False)
    assert intel.verify_bot("66.249.66.1", "Googlebot/2.1") is None


def test_vercel_mode_uses_forwarded_ip(client, monkeypatch):
    from app import main
    monkeypatch.setattr(config, "ON_VERCEL", True)
    monkeypatch.setattr(config, "RATE_LIMIT_COUNT", 1)
    h1 = {"x-real-ip": "203.0.113.1"}
    h2 = {"x-real-ip": "203.0.113.2"}
    body = {"file": ("a.log", COMBINED.encode())}
    assert client.post("/api/analyze", files=body, headers=h1).status_code == 200
    assert client.post("/api/analyze", files=body, headers=h1).status_code == 429   # 같은 사람
    assert client.post("/api/analyze", files=body, headers=h2).status_code == 200   # 다른 사람
    assert main._client_ip.__name__ == "_client_ip"


def test_gzip_upload_through_web(client):
    res = client.post("/api/analyze", files={"file": ("access.log", gzip.compress(SAMPLE.read_bytes()))})
    assert res.status_code == 200 and res.json()["summary"]["flagged"] == 7


def test_story_and_korean_time():
    from app.explain import build_story
    p = parse_path(str(SAMPLE))
    r = analyze(p.df, p.fmt)
    assert r["summary"]["start"].endswith("+09:00") and r["summary"]["tz_offset_min"] == 540
    story = build_story(r)
    assert story["headline"] == "7곳에서 수상한 접속을 찾았어요" and story["mood"] == "alert"
    assert story["todo"] and all(t["title"] for t in story["todo"])
    calm = build_story({"ips": [], "summary": {"levels": {}, "flagged": 0, "ips": 3}})
    assert calm["mood"] == "calm"
