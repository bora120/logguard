"""
웹 서버 접속 로그 파서

- Apache/Nginx 기본 형식(Combined, Common, Nginx main + X-Forwarded-For)을 자동으로 감지한다.
- 사용자 지정 형식도 지원한다. Apache LogFormat(%h %t "%r" ...) 또는 Nginx log_format($remote_addr ...) 문자열을 그대로 넣으면 된다.
- CDN·프록시 뒤 서버라면 X-Forwarded-For 의 실제 접속자 IP를 쓸 수 있다.
- .gz 압축 파일도 읽는다. (압축 폭탄 방지를 위해 '푼 뒤 크기'도 제한)
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import re
from dataclasses import dataclass, field

import pandas as pd

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
DETECT_SAMPLE_LINES = 300
DETECT_MIN_RATIO = 0.5
XFF_AUTO_RATIO = 0.3

PRESETS = {
    "nginx_xff": '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_x_forwarded_for"',
    "combined": '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"',
    "common": '%h %l %u %t "%r" %>s %b',
}
PRESET_LABELS = {"nginx_xff": "Nginx main (+X-Forwarded-For)", "combined": "Combined", "common": "Common",
                 "custom": "사용자 지정"}

QUOTED = r'(?:[^"\\]|\\.)*'
REQUEST = r'(?P<method>[A-Z]+) (?P<url>\S+)(?: [^"]*)?'

# 토큰 → (필드 이름, 정규식). 필드 이름이 None 이면 버리는 값.
APACHE_TOKENS = {
    "h": ("ip", r"\S+"), "a": ("ip", r"\S+"),
    "t": ("time", r"\[[^\]]+\]"),
    "r": ("request", REQUEST),
    ">s": ("status", r"\d{3}"), "s": ("status", r"\d{3}"),
    "b": ("size", r"\S+"), "B": ("size", r"\S+"), "O": ("size", r"\S+"),
}
APACHE_HEADERS = {"referer": "referer", "user-agent": "agent", "x-forwarded-for": "xff",
                  "x-real-ip": "xff", "cf-connecting-ip": "xff"}
NGINX_TOKENS = {
    "remote_addr": ("ip", r"\S+"),
    "time_local": ("time", r"[^\]]+"),
    "time_iso8601": ("time_iso", r"\S+"),
    "request": ("request", REQUEST),
    "status": ("status", r"\d{3}"),
    "body_bytes_sent": ("size", r"\S+"), "bytes_sent": ("size", r"\S+"),
    "http_referer": ("referer", None), "http_user_agent": ("agent", None),
    "http_x_forwarded_for": ("xff", None), "http_x_real_ip": ("xff", None),
    "http_cf_connecting_ip": ("xff", None),
}

TOKEN_RE = re.compile(r"%(?:\{([^}]+)\})?([<>]?[a-zA-Z])|\$([a-zA-Z_][a-zA-Z0-9_]*)")


class LogFormatError(ValueError):
    """지원하지 않는 형식이거나 로그 파일이 아닐 때."""


class LogTooLargeError(ValueError):
    """제한 크기/줄 수를 넘었을 때."""


@dataclass
class ParseResult:
    df: pd.DataFrame
    fmt: str
    total_lines: int
    parsed: int
    skipped: int
    ip_source: str = "remote"
    warnings: list[str] = field(default_factory=list)

    @property
    def has_agent(self) -> bool:
        return bool((self.df["agent"] != "").any())


def compile_format(fmt: str) -> re.Pattern:
    """Apache LogFormat / Nginx log_format 문자열을 정규식으로 바꾼다."""
    fmt = fmt.strip().strip("'")
    fmt = fmt.replace('\\"', '"')
    out, pos, in_quote, used = [], 0, False, set()
    for m in TOKEN_RE.finditer(fmt):
        literal = fmt[pos:m.start()]
        out.append(re.escape(literal).replace("\\ ", " ").replace(" ", r"\s+"))
        in_quote ^= literal.count('"') % 2 == 1
        pos = m.end()
        arg, apache, nginx = m.groups()
        name, rx = None, None
        if nginx:
            name, rx = NGINX_TOKENS.get(nginx, (None, None))
        elif arg is not None:
            low = arg.lower()
            if apache.endswith("t"):                 # %{format}t
                name, rx = ("time", r"\[[^\]]+\]")
            elif apache.endswith("i"):
                name = APACHE_HEADERS.get(low)
        else:
            name, rx = APACHE_TOKENS.get(apache, (None, None))
        if rx is None:
            rx = QUOTED if in_quote else r"\S+"
        if name and name not in used:
            used.add(name)
            out.append(rx if name == "request" else f"(?P<{name}>{rx})")
        else:
            out.append(f"(?:{rx.replace('(?P<method>', '(?:').replace('(?P<url>', '(?:')})")
    tail = fmt[pos:]
    out.append(re.escape(tail).replace("\\ ", " ").replace(" ", r"\s+"))
    missing = {"ip", "request", "status"} - used
    if missing or not ({"time", "time_iso"} & used):
        raise LogFormatError("로그 형식에 접속 IP, 시간, 요청($request 또는 %r), 상태 코드가 모두 있어야 합니다.")
    return re.compile("^" + "".join(out))


PRESET_RE = {k: compile_format(v) for k, v in PRESETS.items()}


def _open_text(raw: io.BufferedIOBase) -> io.TextIOBase:
    head = raw.read(2)
    raw.seek(0)
    stream = gzip.GzipFile(fileobj=raw, mode="rb") if head == b"\x1f\x8b" else raw
    return io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline=None)


def _detect(lines: list[str], custom: re.Pattern | None) -> tuple[str, re.Pattern]:
    sample = [ln for ln in lines if ln.strip()][:DETECT_SAMPLE_LINES]
    if not sample:
        raise LogFormatError("파일이 비어 있습니다.")
    candidates = [("custom", custom)] if custom else list(PRESET_RE.items())
    for name, rx in candidates:
        if sum(bool(rx.match(ln)) for ln in sample) / len(sample) >= DETECT_MIN_RATIO:
            return name, rx
    if custom:
        raise LogFormatError("입력한 로그 형식과 파일 내용이 맞지 않습니다. 서버 설정의 LogFormat/log_format 을 그대로 복사했는지 확인해 주세요.")
    raise LogFormatError("Apache/Nginx 접속 로그로 인식되지 않습니다. 형식을 바꿔 쓰고 있다면 '고급 설정'에 로그 형식을 입력해 주세요.")


def _first_ip(xff: str) -> str:
    for part in xff.split(","):
        part = part.strip()
        try:
            ipaddress.ip_address(part)
            return part
        except ValueError:
            continue
    return ""


def parse_stream(raw: io.BufferedIOBase, max_bytes: int, max_lines: int,
                 log_format: str | None = None, ip_source: str = "auto") -> ParseResult:
    """업로드된 파일 객체(바이너리)를 읽어 DataFrame 으로 만든다."""
    custom = compile_format(log_format) if log_format and log_format.strip() else None
    rows: list[dict] = []
    head: list[str] = []
    total = skipped = read_bytes = 0
    fmt, pattern = None, None

    def handle(line: str):
        nonlocal skipped
        m = pattern.match(line)
        if m:
            rows.append(m.groupdict())
        else:
            skipped += 1

    try:
        for line in _open_text(raw):
            read_bytes += len(line)
            if read_bytes > max_bytes:
                raise LogTooLargeError(f"압축을 푼 로그가 {max_bytes // (1024 * 1024)}MB를 넘습니다.")
            if not line.strip():
                continue
            total += 1
            if total > max_lines:
                raise LogTooLargeError(f"로그가 {max_lines:,}줄을 넘습니다.")
            if fmt is None:
                head.append(line)
                if len(head) >= DETECT_SAMPLE_LINES:
                    fmt, pattern = _detect(head, custom)
                    for h in head:
                        handle(h)
                continue
            handle(line)
        if fmt is None:
            fmt, pattern = _detect(head, custom)
            for h in head:
                handle(h)
    except (gzip.BadGzipFile, EOFError, OSError) as e:
        raise LogFormatError(f"압축 파일을 읽을 수 없습니다: {e}") from e

    df = pd.DataFrame(rows)
    for col in ("referer", "agent", "xff", "size"):
        if col not in df:
            df[col] = ""
    df[["referer", "agent", "xff"]] = df[["referer", "agent", "xff"]].fillna("")
    warnings: list[str] = []

    # 실제 접속자 IP 선택
    used_xff = "remote"
    xff_ip = df["xff"].map(_first_ip)
    xff_share = float((xff_ip != "").mean()) if len(df) else 0.0
    if ip_source == "xff" or (ip_source == "auto" and xff_share >= XFF_AUTO_RATIO):
        if xff_share > 0:
            df["peer"] = df["ip"]
            df["ip"] = xff_ip.where(xff_ip != "", df["ip"])
            used_xff = "xff"
            warnings.append(f"X-Forwarded-For 의 실제 접속자 IP 기준으로 분석했습니다. (요청의 {xff_share:.0%}에 값이 있음)")
        elif ip_source == "xff":
            warnings.append("X-Forwarded-For 값이 없어 접속 주소 기준으로 분석했습니다.")

    # 시간
    if "time_iso" in df:
        df["time"] = pd.to_datetime(df["time_iso"], format="ISO8601", errors="coerce", utc=True)
    else:
        df["time"] = pd.to_datetime(df["time"].str.strip("[]"), format=TIME_FORMAT, errors="coerce", utc=True)
    bad = int(df["time"].isna().sum())
    if bad:
        df = df.dropna(subset=["time"])
        skipped += bad
    df["status"] = df["status"].astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype("int64")
    df = df[["ip", "time", "method", "url", "status", "size", "referer", "agent"]].reset_index(drop=True)

    if not (df["agent"] != "").any():
        warnings.append("User-Agent 정보가 없어 '공격 도구 사용'·검색봇 판별은 건너뜁니다.")
    if total and skipped / total > 0.2:
        warnings.append(f"전체 {total:,}줄 중 {skipped:,}줄은 형식이 맞지 않아 제외했습니다.")
    if df.empty:
        raise LogFormatError("분석할 수 있는 요청이 없습니다.")

    return ParseResult(df=df, fmt=fmt, total_lines=total, parsed=len(df), skipped=skipped,
                       ip_source=used_xff, warnings=warnings)


def parse_path(path: str, max_bytes: int = 1024 ** 3, max_lines: int = 10_000_000,
               log_format: str | None = None, ip_source: str = "auto") -> ParseResult:
    with open(path, "rb") as f:
        return parse_stream(f, max_bytes=max_bytes, max_lines=max_lines,
                            log_format=log_format, ip_source=ip_source)
