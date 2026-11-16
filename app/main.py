"""
LogGuard 웹 서비스

- 업로드된 로그는 디스크에 저장하지 않고, 분석이 끝나면 즉시 폐기한다.
- 결과 화면은 Jinja2 자동 이스케이프로 렌더링한다. (로그 속 공격 문자열로 인한 XSS 방지)
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config
from .engine.analyzer import analyze
from .engine.intel import default_geo, enrich, verify_bot
from .explain import GLOSSARY, LEVELS, RULES, STATUS_CODES, build_story
from .engine.parser import PRESET_LABELS, LogFormatError, LogTooLargeError, parse_path, parse_stream

BASE = Path(__file__).resolve().parent
SAMPLE_LOG = BASE / "sample" / "sample_access.log"

app = FastAPI(title=config.APP_NAME, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals.update(app_name=config.APP_NAME, max_mb=config.MAX_UPLOAD_MB,
                             contact=config.CONTACT_EMAIL, abuse_enabled=bool(config.ABUSEIPDB_KEY),
                             abuse_max=config.ABUSEIPDB_MAX, geo_enabled=default_geo().available,
                             format_labels=PRESET_LABELS, RULES=RULES, LEVELS=LEVELS,
                             GLOSSARY=GLOSSARY, STATUS_CODES=STATUS_CODES)


def _when(iso: str, with_date: bool = True) -> str:
    """'2026-11-16T15:15:30+09:00' → '11월 16일 15:15:30'"""
    if not iso:
        return ""
    m, d, t = int(iso[5:7]), int(iso[8:10]), iso[11:19]
    return f"{m}월 {d}일 {t}" if with_date else t


templates.env.filters["when"] = _when
templates.env.filters["clock"] = lambda iso: _when(iso, False)
templates.env.filters["num"] = lambda n: f"{n:,}"


@lru_cache(maxsize=64)
def _asset(path: str) -> str:
    """'/static/style.css' → '/static/style.css?v=<내용 해시>'.
    파일 내용이 바뀌면 주소도 바뀌어서, 브라우저가 예전 CSS·JS를 붙잡고 있지 않는다."""
    f = BASE / path.removeprefix("/").split("?")[0]
    try:
        digest = hashlib.sha256(f.read_bytes()).hexdigest()[:10]
    except OSError:
        return path
    return f"{path}?v={digest}"


templates.env.filters["asset"] = _asset

_slots = threading.BoundedSemaphore(config.MAX_CONCURRENT)
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/static/"):
        # 글꼴·그래프 라이브러리처럼 잘 바뀌지 않는 파일은 브라우저가 하루 동안 다시 받지 않게 한다
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    else:
        response.headers["Cache-Control"] = "no-store"   # 분석 결과 페이지는 캐시에 남기지 않는다
    return response


def _rate_limited(client: str) -> bool:
    now = time.time()
    with _hits_lock:
        q = _hits[client]
        while q and now - q[0] > config.RATE_LIMIT_WINDOW:
            q.popleft()
        if len(q) >= config.RATE_LIMIT_COUNT:
            return True
        q.append(now)
        return False


def _run(parse_fn, use_abuse: bool = False):
    if not _slots.acquire(timeout=30):
        raise HTTPException(503, "지금 분석 요청이 많아요. 잠시 뒤에 다시 시도해 주세요.")
    try:
        parsed = parse_fn()
        result = analyze(parsed.df, parsed.fmt,
                         bot_verifier=verify_bot if config.VERIFY_BOTS else None,
                         display_tz=config.DISPLAY_TZ)
        enrich(result, abuse_key=config.ABUSEIPDB_KEY if use_abuse else None,
               abuse_max=config.ABUSEIPDB_MAX)
        result["story"] = build_story(result)
        result["meta"] = {"format": parsed.fmt, "total_lines": parsed.total_lines,
                          "parsed": parsed.parsed, "skipped": parsed.skipped,
                          "ip_source": parsed.ip_source, "warnings": parsed.warnings}
        return result
    finally:
        _slots.release()


def _client_ip(request: Request) -> str:
    if config.ON_VERCEL:   # Vercel 프록시가 실제 접속자 IP를 헤더로 넘겨준다
        ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0]
        if ip.strip():
            return ip.strip()
    return request.client.host if request.client else "unknown"


def _analyze_upload(request: Request, file: UploadFile, log_format: str = "",
                    ip_source: str = "auto", abuse: bool = False) -> dict:
    client = _client_ip(request)
    if _rate_limited(client):
        raise HTTPException(429, f"분석은 {config.RATE_LIMIT_WINDOW // 60}분에 "
                                 f"{config.RATE_LIMIT_COUNT}번까지 할 수 있어요. 잠시 뒤에 다시 시도해 주세요.")
    if file.size is not None and file.size > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"파일은 압축한 뒤 {config.MAX_UPLOAD_MB}MB까지 올릴 수 있어요. "
                                 "로그를 날짜별로 나누거나 CLI 버전으로 분석해 주세요.")
    if len(log_format) > config.MAX_FORMAT_LEN:
        raise HTTPException(400, "로그 형식이 너무 길어요. 500자 안으로 넣어 주세요.")
    if ip_source not in ("auto", "remote", "xff"):
        ip_source = "auto"
    try:
        return _run(lambda: parse_stream(file.file,
                                         max_bytes=config.MAX_DECOMPRESSED_MB * 1024 * 1024,
                                         max_lines=config.MAX_LINES,
                                         log_format=log_format or None, ip_source=ip_source),
                    use_abuse=abuse and bool(config.ABUSEIPDB_KEY))
    except LogTooLargeError as e:
        raise HTTPException(413, str(e))
    except LogFormatError as e:
        raise HTTPException(400, str(e))
    finally:
        file.file.close()  # 임시 버퍼 즉시 폐기


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/analyze", response_class=HTMLResponse)
def analyze_page(request: Request, file: UploadFile = File(...), log_format: str = Form(""),
                 ip_source: str = Form("auto"), abuse: str = Form("")):
    try:
        result = _analyze_upload(request, file, log_format, ip_source, abuse == "on")
    except HTTPException as e:
        return templates.TemplateResponse(request, "index.html", {"error": e.detail},
                                          status_code=e.status_code)
    return templates.TemplateResponse(request, "report.html",
                                      {"r": result, "filename": file.filename or "업로드한 로그"})


@app.post("/api/analyze")
def analyze_api(request: Request, file: UploadFile = File(...), log_format: str = Form(""),
                ip_source: str = Form("auto"), abuse: str = Form("")):
    return JSONResponse(_analyze_upload(request, file, log_format, ip_source, abuse in ("on", "1", "true")))


@app.get("/sample", response_class=HTMLResponse)
def sample_report(request: Request):
    result = _run(lambda: parse_path(str(SAMPLE_LOG)))
    return templates.TemplateResponse(request, "report.html",
                                      {"r": result, "filename": "샘플 로그 (테스트용 가상 트래픽)",
                                       "is_sample": True})


@app.get("/sample/download")
def sample_download():
    return FileResponse(SAMPLE_LOG, filename="sample_access.log", media_type="text/plain")


@app.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    return templates.TemplateResponse(request, "privacy.html")


@app.get("/favicon.ico")
def favicon():
    return FileResponse(BASE / "static" / "favicon.svg", media_type="image/svg+xml")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)
    detail = "페이지를 찾을 수 없어요." if exc.status_code == 404 else exc.detail
    return templates.TemplateResponse(request, "index.html", {"error": detail},
                                      status_code=exc.status_code)
