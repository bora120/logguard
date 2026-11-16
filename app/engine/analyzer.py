"""
탐지 엔진

1) 요청마다 위험 표시(민감 경로, 공격 패턴, 공격 도구 UA 등)를 붙인다.
2) IP 단위로 묶어 규칙 7가지를 검사한다.
3) IP의 활동을 '세션'(30분 이상 쉬면 새 세션)으로 나눠 AI(Isolation Forest)가 세션마다 이상 여부를 본다.
   → 평소엔 정상이던 IP가 특정 시간대에만 공격한 경우도 묻히지 않는다.
4) 위험도·탐지 사유·대응 방법·공격 구간을 담은 보고서를 만든다.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Callable
from urllib.parse import unquote

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── 기준값 ───────────────────────────────────────────────────
WINDOW = "60s"
FLOOD_LIMIT = 100
FLOOD_HIGH = 300
SCAN_404_LIMIT = 10
LOGIN_LIMIT = 20
SESSION_GAP = pd.Timedelta(minutes=30)
ML_MIN_IPS = 10
ML_MIN_REQUESTS = 5
MAX_BOT_CHECKS = 30

SENSITIVE_RE = re.compile(
    r"/(?:\.env|\.git|\.svn|\.htpasswd|\.htaccess|\.ds_store|wp-admin|"
    r"wp-config|xmlrpc\.php|phpmyadmin|pma/|adminer|admin(?:istrator)?/|config\.(?:php|json|yml)|"
    r"backup|\.bak\b|\.sql\b|db\.|dump|server-status|shell|cmd\.php|eval|cgi-bin|"
    r"info\.php|phpinfo|etc/passwd|\.aws|id_rsa)",
    re.IGNORECASE,
)
TOOL_UA_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb\b|wfuzz|ffuf|hydra|"
    r"acunetix|nessus|openvas|w3af|nuclei|wpscan|havij|jaeles|xray",
    re.IGNORECASE,
)
ATTACK_RE = re.compile(
    r"(?:'|%27)\s*(?:or|and)\s*'?\d|union(?:\s|/\*.*?\*/)+select|drop\s+table|"
    r"sleep\s*\(|benchmark\s*\(|information_schema|<script|javascript:|onerror\s*=|"
    r"\.\./|\.\.%2f|%2e%2e|/etc/passwd|\$\{jndi:|;\s*(?:ls|cat|wget|curl)\s",
    re.IGNORECASE,
)
LOGIN_RE = re.compile(r"login|signin|sign-in|auth|wp-login\.php|xmlrpc\.php", re.IGNORECASE)
BOT_RE = re.compile(
    r"googlebot|bingbot|yeti|naverbot|daum|applebot|duckduckbot|baiduspider|yandex|"
    r"slurp|facebookexternalhit|twitterbot|linkedinbot|kakaotalk-scrap",
    re.IGNORECASE,
)
SPECIAL_PATTERN = r"""['"<>()*;|%=]"""

LEVEL_ORDER = {"높음": 3, "중간": 2, "낮음": 1}

ACTIONS = {
    "flood": "웹 서버에 요청 속도 제한을 거세요. (Nginx: limit_req, Apache: mod_evasive) CDN을 쓰고 있다면 Rate Limiting 기능을 켜세요.",
    "scan": "존재하지 않는 경로를 대량으로 탐색하는 IP입니다. fail2ban 등으로 반복 404 IP를 일시 차단하세요.",
    "sensitive": "요청된 민감 파일(.env, .git, 백업 파일 등)이 실제로 외부에서 열리는지 확인하고, 웹 루트 밖으로 옮기세요.",
    "tool": "자동화 공격 도구입니다. WAF(예: ModSecurity + OWASP CRS)를 적용하세요. UA 차단은 쉽게 우회되므로 보조 수단입니다.",
    "attack": "입력값 검증과 Prepared Statement 사용을 확인하세요. 응답이 200이면 실제로 공격이 처리됐을 수 있으니 우선 점검하세요.",
    "brute": "로그인 시도 횟수 제한, CAPTCHA, 2단계 인증을 적용하세요. fail2ban으로 반복 시도 IP를 차단할 수 있습니다.",
    "fakebot": "검색엔진 봇을 사칭한 접속입니다. User-Agent만 보고 봇을 허용하는 설정이 있다면 역방향 DNS 검증으로 바꾸세요.",
    "ml": "규칙에는 걸리지 않았지만 다른 접속자와 행동이 크게 다릅니다. 표시된 구간의 요청을 직접 확인해 보세요.",
}

FEATURE_LABELS = {
    "requests": "요청 수",
    "peak_60s": "60초 최대 요청 수",
    "err_ratio": "오류 응답(4xx/5xx) 비율",
    "unique_url_ratio": "서로 다른 URL 비율",
    "login_ratio": "로그인 경로 요청 비율",
    "query_ratio": "파라미터 포함 요청 비율",
    "avg_url_len": "평균 URL 길이",
    "special_chars": "URL 특수문자 수",
    "rate_per_min": "분당 요청 속도",
}
ML_FEATURES = list(FEATURE_LABELS)

# 봇 진위 확인 함수 형식: (ip, user_agent) -> True(진짜) / False(사칭) / None(확인 불가)
BotVerifier = Callable[[str, str], "bool | None"]


@dataclass
class Finding:
    rule: str
    name: str
    level: str
    reason: str
    action: str
    start: str = ""
    end: str = ""


# ── 요청 단위 표시 ────────────────────────────────────────────
def _per_unique(col: pd.Series, fn) -> np.ndarray:
    """같은 값이 반복되는 열(URL, User-Agent)은 고유값에만 계산하고 펼친다. 실제 로그에서 수십 배 빠르다."""
    codes, uniques = pd.factorize(col, sort=False)
    return np.asarray(fn(pd.Series(uniques, dtype=object)))[codes]


def mark_requests(df: pd.DataFrame) -> pd.DataFrame:
    d = df.sort_values(["ip", "time"], kind="stable").reset_index(drop=True)

    def url_flags(u: pd.Series) -> pd.DataFrame:
        dec = u.map(unquote)
        return pd.DataFrame({
            "url_dec": dec,
            "is_login": dec.str.contains(LOGIN_RE),
            "has_query": u.str.contains("?", regex=False),
            "url_len": u.str.len(),
            "special": dec.str.count(SPECIAL_PATTERN),
            "is_sensitive": dec.str.contains(SENSITIVE_RE),
            "is_attack": dec.str.contains(ATTACK_RE) | u.str.contains(ATTACK_RE),
        })

    codes, uniques = pd.factorize(d["url"], sort=False)
    uf = url_flags(pd.Series(uniques, dtype=object)).iloc[codes].reset_index(drop=True)
    d = pd.concat([d, uf], axis=1)
    d["is_err"] = d["status"] >= 400
    d["is_404"] = d["status"] == 404
    d["is_tool"] = _per_unique(d["agent"], lambda a: a.str.contains(TOOL_UA_RE))
    d["is_bot"] = _per_unique(d["agent"], lambda a: a.str.contains(BOT_RE))
    # 세션: 같은 IP라도 30분 이상 쉬었다 오면 새 세션
    gap = d.groupby("ip")["time"].diff()
    d["sess"] = (gap.isna() | (gap > SESSION_GAP)).astype(int).groupby(d["ip"]).cumsum()
    d["sess_key"] = d["ip"] + "#" + d["sess"].astype(str)
    return d


def _rolling_peak(d: pd.DataFrame, key: str, window_s: float = 60.0) -> pd.Series:
    """key별로 60초 구간 최대 요청 수. (d는 key, time 순으로 정렬돼 있어야 함)

    키마다 시간축을 1e9초씩 떨어뜨려 한 줄로 이어 붙인 뒤 searchsorted 로 구간 개수를 한 번에 센다.
    그룹이 수십만 개여도 빠르다.
    """
    if d.empty:
        return pd.Series(dtype="int64")
    codes, uniques = pd.factorize(d[key], sort=False)
    t = (d["time"] - d["time"].min()).dt.total_seconds().to_numpy()
    v = codes.astype("float64") * 1e9 + t
    order = np.argsort(v, kind="stable")
    v_sorted = v[order]
    left = np.searchsorted(v_sorted, v_sorted - window_s, side="right")
    counts = np.arange(len(v_sorted)) - left + 1
    peak = pd.Series(counts).groupby(codes[order]).max()
    return pd.Series(peak.to_numpy(), index=uniques[peak.index]).astype("int64")


def aggregate(d: pd.DataFrame, key: str) -> pd.DataFrame:
    g = d.groupby(key)
    f = pd.DataFrame({
        "ip": g["ip"].first(),
        "requests": g.size(),
        "err_ratio": g["is_err"].mean(),
        "n404": g["is_404"].sum(),
        "n_err": g["is_err"].sum(),
        "n_login": g["is_login"].sum(),
        "unique_url_ratio": g["url"].nunique() / g.size(),
        "login_ratio": g["is_login"].mean(),
        "query_ratio": g["has_query"].mean(),
        "avg_url_len": g["url_len"].mean(),
        "special_chars": g["special"].mean(),
        "sensitive": g["is_sensitive"].sum(),
        "attack": g["is_attack"].sum(),
        "tool": g["is_tool"].sum(),
        "bot_ratio": g["is_bot"].mean(),
        "first_seen": g["time"].min(),
        "last_seen": g["time"].max(),
    })
    f["attack_ok"] = d[d["is_attack"] & (d["status"] < 400)].groupby(key).size().reindex(f.index).fillna(0).astype("int64")
    f["peak_60s"] = _rolling_peak(d, key).reindex(f.index).fillna(0).astype("int64")
    f["peak_login_60s"] = _rolling_peak(d[d["is_login"]], key).reindex(f.index).fillna(0).astype("int64")
    span_min = ((f["last_seen"] - f["first_seen"]).dt.total_seconds() / 60).clip(lower=1)
    f["rate_per_min"] = f["requests"] / span_min
    return f


def _span(rows: pd.DataFrame) -> tuple[str, str]:
    if rows.empty:
        return "", ""
    return rows["time"].min().isoformat(), rows["time"].max().isoformat()


# ── 규칙 ─────────────────────────────────────────────────────
def _apply_rules(f: pd.DataFrame, d: pd.DataFrame, has_agent: bool,
                 bot_status: dict[str, bool | None]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    by_ip = dict(tuple(d.groupby("ip")))

    def add(ip, rule, name, level, reason, action, mask_col=None):
        rows = by_ip[ip]
        if mask_col:
            rows = rows[rows[mask_col]]
        out.setdefault(ip, []).append(Finding(rule, name, level, reason, action, *_span(rows)))

    for ip, r in f.iterrows():
        claimed_bot = has_agent and r["bot_ratio"] >= 0.8
        verdict = bot_status.get(ip)
        exempt = claimed_bot and verdict is not False
        if claimed_bot and verdict is False:
            add(ip, "R7", "검색봇 사칭", "중간",
                "검색엔진 봇이라고 밝혔지만 역방향 DNS 검증에 실패했습니다", ACTIONS["fakebot"])
        if r["peak_60s"] >= FLOOD_LIMIT and not exempt:
            lvl = "높음" if r["peak_60s"] >= FLOOD_HIGH else "중간"
            add(ip, "R1", "과도한 요청", lvl, f"60초 안에 최대 {r['peak_60s']:,}회 요청", ACTIONS["flood"])
        if r["n404"] >= SCAN_404_LIMIT:
            add(ip, "R2", "경로 스캔", "중간", f"존재하지 않는 경로(404) {int(r['n404']):,}회 요청",
                ACTIONS["scan"], "is_404")
        if r["sensitive"] >= 1:
            lvl = "높음" if r["sensitive"] >= 5 else "중간"
            add(ip, "R3", "민감 경로 접근", lvl, f"민감 파일·관리자 경로 {int(r['sensitive']):,}회 요청",
                ACTIONS["sensitive"], "is_sensitive")
        if has_agent and r["tool"] >= 1:
            add(ip, "R4", "공격 도구 사용", "높음", f"공격 도구 User-Agent로 {int(r['tool']):,}회 요청",
                ACTIONS["tool"], "is_tool")
        if r["attack"] >= 1:
            extra = f" (그중 {int(r['attack_ok'])}건은 정상 응답 → 우선 점검)" if r["attack_ok"] else ""
            add(ip, "R5", "공격 패턴", "높음", f"SQL 인젝션·XSS·경로 조작 패턴 {int(r['attack']):,}회{extra}",
                ACTIONS["attack"], "is_attack")
        if r["peak_login_60s"] >= LOGIN_LIMIT:
            add(ip, "R6", "무차별 대입 의심", "높음", f"60초 안에 로그인 경로 {r['peak_login_60s']:,}회 요청",
                ACTIONS["brute"], "is_login")
    return out


# ── AI (세션 단위) ───────────────────────────────────────────
def _risky_evidence(f: pd.DataFrame, z: pd.DataFrame) -> pd.Series:
    """AI가 '특이하다'고 본 세션 중 공격 쪽으로 특이하고 근거가 충분한 경우만 남긴다."""
    return (
        ((f["n_login"] >= 10) & (f["login_ratio"] >= 0.5))
        | ((f["n_err"] >= 5) & (f["err_ratio"] >= 0.5))
        | ((f["special_chars"] >= 1.0) & (f["query_ratio"] >= 0.5))
        | ((z["peak_60s"] >= 3) & (f["peak_60s"] >= 30))
        | ((f["unique_url_ratio"] >= 0.9) & (f["requests"] >= 15) & (z["unique_url_ratio"] >= 2))
        | ((z["avg_url_len"] >= 3) & (f["avg_url_len"] >= 60))
    )


def _apply_ml(s: pd.DataFrame, n_ips: int, exempt_ips: set[str]):
    # 요청이 너무 적은 세션은 판단 근거가 부족하므로 학습·판정에서 뺀다 (오탐 방지 + 속도)
    s = s[s["requests"] >= ML_MIN_REQUESTS]
    if n_ips < ML_MIN_IPS or len(s) < ML_MIN_IPS:
        return None
    X = s[ML_FEATURES].astype(float).copy()
    for col in ("requests", "peak_60s", "rate_per_min", "avg_url_len"):
        X[col] = np.log1p(X[col])
    Z = np.nan_to_num(StandardScaler().fit_transform(X))
    model = IsolationForest(n_estimators=300, contamination="auto", random_state=42).fit(Z)
    score = pd.Series(-model.score_samples(Z), index=s.index)
    zdf = pd.DataFrame(Z, index=s.index, columns=ML_FEATURES)
    flag = pd.Series(model.decision_function(Z) < 0, index=s.index)
    flag &= s["requests"] >= ML_MIN_REQUESTS
    flag &= ~s["ip"].isin(exempt_ips)
    flag &= _risky_evidence(s, zdf)
    return score, flag, zdf


def _explain(zrow: pd.Series, frow: pd.Series, top: int = 2) -> str:
    risky = zrow.drop(labels=["requests"])
    risky = risky[risky > 0].sort_values(ascending=False)
    parts = []
    for col in risky.index[:top]:
        val = frow[col]
        shown = f"{val * 100:.0f}%" if col.endswith("ratio") else (f"{val:.1f}" if isinstance(val, float) else f"{val:,}")
        parts.append(f"{FEATURE_LABELS[col]} 높음({shown})")
    return "다른 접속자와 비교해 " + ", ".join(parts)


def _period_freq(span_seconds: float) -> str:
    for freq, sec in (("5s", 5), ("10s", 10), ("30s", 30), ("1min", 60), ("5min", 300), ("15min", 900),
                      ("1h", 3600), ("6h", 21600), ("1D", 86400)):
        if span_seconds / sec <= 120:
            return freq
    return "7D"


def _fmt_range(a: str, b: str) -> str:
    a, b = a[:19].replace("T", " "), b[:19].replace("T", " ")
    return f"{a} ~ {b[11:] if a[:10] == b[:10] else b}"


# ── 보고서 정리 (위험도·정렬·요약) ─────────────────────────────
def level_of(findings: list[dict]) -> str:
    level = max((x["level"] for x in findings), key=LEVEL_ORDER.get)
    if len({x["rule"] for x in findings} - {"AI"}) >= 3:
        level = "높음"
    return level


def finalize(result: dict) -> dict:
    """IP 목록의 위험도를 다시 계산하고 정렬, 요약 숫자를 갱신한다. (위협 정보 연동 후에도 호출)"""
    for ip in result["ips"]:
        ip["level"] = level_of(ip["findings"])
        starts = [f["start"] for f in ip["findings"] if f["start"]] or [ip["stats"]["first_seen"]]
        ends = [f["end"] for f in ip["findings"] if f["end"]] or [ip["stats"]["last_seen"]]
        ip["window"] = {"start": min(starts), "end": max(ends)}
    result["ips"].sort(key=lambda x: (-LEVEL_ORDER[x["level"]], -len(x["findings"]),
                                      -(x["ml_score"] or 0), -x["stats"]["requests"]))
    result["summary"]["levels"] = {k: sum(i["level"] == k for i in result["ips"]) for k in LEVEL_ORDER}
    counts: dict[str, int] = {}
    for ip in result["ips"]:
        for name in {f["name"] for f in ip["findings"]}:
            counts[name] = counts.get(name, 0) + 1
    result["rule_counts"] = counts
    return result


def analyze(df: pd.DataFrame, fmt: str = "combined", max_ip_reports: int = 200,
            bot_verifier: BotVerifier | None = None, display_tz: str = "Asia/Seoul") -> dict:
    df = df.assign(time=df["time"].dt.tz_convert(display_tz))   # 보고서는 보기 편한 시간대로 표시
    d = mark_requests(df)
    has_agent = bool((d["agent"] != "").any())
    f = aggregate(d, "ip")
    f["agent"] = d.groupby("ip")["agent"].agg(lambda s: s.mode().iat[0] if len(s) else "")

    # 검색봇 진위 확인 (UA가 봇이라고 주장하는 IP만, 개수 제한)
    bot_status: dict[str, bool | None] = {}
    claimed = f.index[(f["bot_ratio"] >= 0.8)] if has_agent else []
    targets = list(claimed)[:MAX_BOT_CHECKS]
    if bot_verifier and targets:
        with ThreadPoolExecutor(max_workers=8) as ex:
            verdicts = ex.map(lambda ip: bot_verifier(ip, f.at[ip, "agent"]), targets)
            bot_status = dict(zip(targets, verdicts))
    else:
        bot_status = {ip: None for ip in targets}
    exempt = {ip for ip in claimed if bot_status.get(ip) is not False}

    rule_hits = _apply_rules(f, d, has_agent, bot_status)

    s = aggregate(d, "sess_key")
    ml = _apply_ml(s, len(f), exempt)
    ml_hits: dict[str, Finding] = {}
    ml_ip_score: dict[str, float] = {}
    if ml:
        score, flag, zdf = ml
        ml_ip_score = score.groupby(s.loc[score.index, "ip"]).max().to_dict()
        for key in score[flag].sort_values(ascending=False).index:
            ip = s.at[key, "ip"]
            if ip in ml_hits:
                continue
            a, b = s.at[key, "first_seen"].isoformat(), s.at[key, "last_seen"].isoformat()
            n_sess = int((s["ip"] == ip).sum())
            where = f" · {_fmt_range(a, b)} 구간" if n_sess > 1 else ""
            ml_hits[ip] = Finding("AI", "AI 이상 행위", "낮음",
                                  _explain(zdf.loc[key], s.loc[key]) + where, ACTIONS["ml"], a, b)

    by_ip = dict(tuple(d.groupby("ip")))
    ips = []
    for ip in set(rule_hits) | set(ml_hits):
        findings = list(rule_hits.get(ip, []))
        if ip in ml_hits:
            ai = ml_hits[ip]
            if findings:
                ai.level = "중간"
            findings.append(ai)
        r, sub = f.loc[ip], by_ip[ip]
        bad = sub[sub["is_attack"] | sub["is_sensitive"] | sub["is_err"] | sub["is_tool"]]
        sample_rows = (bad if len(bad) else sub).head(8)
        ips.append({
            "ip": ip,
            "level": "",
            "ml_score": round(float(ml_ip_score[ip]), 3) if ip in ml_ip_score else None,
            "findings": [asdict(x) for x in findings],
            "bot": None if ip not in bot_status else {True: "검증됨", False: "사칭", None: "미검증"}[bot_status[ip]],
            "stats": {
                "requests": int(r["requests"]),
                "peak_60s": int(r["peak_60s"]),
                "err_ratio": round(float(r["err_ratio"]) * 100, 1),
                "sessions": int((s["ip"] == ip).sum()),
                "first_seen": r["first_seen"].isoformat(),
                "last_seen": r["last_seen"].isoformat(),
                "agent": r["agent"][:160],
            },
            "samples": [{"time": t.isoformat(), "method": m, "url": u[:300], "status": int(st)}
                        for t, m, u, st in sample_rows[["time", "method", "url", "status"]].itertuples(index=False)],
            "intel": {},
        })

    # 차트·요약
    span = (d["time"].max() - d["time"].min()).total_seconds()
    freq = _period_freq(span)
    flagged = {x["ip"] for x in ips}
    tl = d.set_index("time").assign(sus=d["ip"].isin(flagged).values).sort_index()
    timeline = tl.resample(freq).agg({"ip": "size", "sus": "sum"}).reset_index()

    result = {
        "summary": {
            "requests": int(len(d)),
            "ips": int(len(f)),
            "sessions": int(len(s)),
            "start": d["time"].min().isoformat(),
            "end": d["time"].max().isoformat(),
            "tz": display_tz,
            "tz_label": "한국 시간" if display_tz == "Asia/Seoul" else display_tz,
            "tz_offset_min": int(d["time"].min().utcoffset().total_seconds() // 60),
            "flagged": len(ips),
            "levels": {},
            "ml_used": ml is not None,
            "bots_checked": sum(v is not None for v in bot_status.values()),
            "status": {str(k): int(v) for k, v in d["status"].value_counts().sort_index().items()},
        },
        "timeline": {
            "freq": freq,
            "freq_label": {"5s": "5초", "10s": "10초", "30s": "30초", "1min": "1분", "5min": "5분", "15min": "15분",
                           "1h": "1시간", "6h": "6시간", "1D": "하루", "7D": "일주일"}[freq],
            "labels": [t.isoformat() for t in timeline["time"]],
            "total": timeline["ip"].astype(int).tolist(),
            "suspicious": timeline["sus"].astype(int).tolist(),
        },
        "top_urls": [{"url": u[:200], "count": int(c)} for u, c in d["url"].value_counts().head(10).items()],
        "top_404": [{"url": u[:200], "count": int(c)}
                    for u, c in d.loc[d["is_404"], "url"].value_counts().head(10).items()],
        "ips": ips,
        "truncated_ips": 0,
        "intel": {},
    }
    finalize(result)
    if len(result["ips"]) > max_ip_reports:
        result["truncated_ips"] = len(result["ips"]) - max_ip_reports
        result["ips"] = result["ips"][:max_ip_reports]
    return result
