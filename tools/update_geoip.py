"""
DB-IP Lite(국가, ASN) 데이터를 최신 버전으로 내려받는다. (매월 갱신, CC BY 4.0)

    python tools/update_geoip.py

1순위: DB-IP 공식 배포 (download.db-ip.com)
2순위: ip-location-db 미러 (jsDelivr)
"""
import gzip
import shutil
import sys
import tempfile
import urllib.request
from datetime import date, timedelta
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "app" / "data"
TARGETS = {
    "dbip-country.mmdb": ("country", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country-mmdb/dbip-country.mmdb"),
    "dbip-asn.mmdb": ("asn", "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-asn-mmdb/dbip-asn.mmdb"),
}


def months():
    today = date.today().replace(day=1)
    yield today.strftime("%Y-%m")
    yield (today - timedelta(days=1)).strftime("%Y-%m")


def fetch(url: str, out: Path) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LogGuard-geoip-updater"})
        with urllib.request.urlopen(req, timeout=60) as res, open(out, "wb") as fp:
            src = gzip.GzipFile(fileobj=res) if url.endswith(".gz") else res
            shutil.copyfileobj(src, fp)
        return out.stat().st_size > 1_000_000
    except Exception as e:
        print(f"  실패: {url} ({e})")
        return False


def check(path: Path) -> bool:
    try:
        import maxminddb
        with maxminddb.open_database(str(path)) as db:
            return db.get("8.8.8.8") is not None
    except Exception as e:
        print(f"  검증 실패: {e}")
        return False


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    ok_all = True
    for name, (kind, mirror) in TARGETS.items():
        print(f"[{name}] 내려받는 중...")
        urls = [f"https://download.db-ip.com/free/dbip-{kind}-lite-{m}.mmdb.gz" for m in months()] + [mirror]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_file = Path(tmp) / name
            for url in urls:
                if fetch(url, tmp_file) and check(tmp_file):
                    shutil.move(str(tmp_file), DEST / name)
                    print(f"  완료: {url}")
                    break
            else:
                ok_all = False
                print("  모든 경로에서 실패했습니다. 기존 파일을 그대로 사용합니다.")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
