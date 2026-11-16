"""
명령줄 버전 — 로그를 외부로 보내지 않고 서버 안에서 바로 분석한다.

사용법:
    python -m app.cli /var/log/apache2/access.log
    python -m app.cli access.log.gz --json result.json --csv result.csv
"""
import argparse
import csv
import json
import sys

from .engine.analyzer import analyze
from .engine.intel import enrich, verify_bot
from .engine.parser import LogFormatError, LogTooLargeError, parse_path

COLOR = {"높음": "\033[31m", "중간": "\033[33m", "낮음": "\033[34m"}
RESET = "\033[0m"


def main(argv=None):
    ap = argparse.ArgumentParser(description="웹 서버 접속 로그 이상 행위 탐지")
    ap.add_argument("logfile", help="Apache/Nginx 접속 로그 (.log 또는 .gz)")
    ap.add_argument("--json", help="전체 결과를 JSON 파일로 저장")
    ap.add_argument("--csv", help="탐지된 IP 목록을 CSV 파일로 저장")
    ap.add_argument("--log-format", help="사용자 지정 로그 형식 (Apache LogFormat 또는 Nginx log_format)")
    ap.add_argument("--ip-source", default="auto", choices=["auto", "remote", "xff"])
    ap.add_argument("--no-bot-check", action="store_true", help="검색봇 역방향 DNS 검증 끄기")
    ap.add_argument("--abuseipdb-key", help="AbuseIPDB API 키 (지정하면 탐지된 IP 평판 조회)")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)

    try:
        p = parse_path(a.logfile, log_format=a.log_format, ip_source=a.ip_source)
    except (LogFormatError, LogTooLargeError, OSError) as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1

    r = analyze(p.df, p.fmt, bot_verifier=None if a.no_bot_check else verify_bot)
    enrich(r, abuse_key=a.abuseipdb_key)
    s = r["summary"]
    c = (lambda lv: "") if a.no_color or not sys.stdout.isatty() else COLOR.get
    reset = "" if a.no_color or not sys.stdout.isatty() else RESET

    print(f"형식: {p.fmt} | 요청 {s['requests']:,}건 | IP {s['ips']:,}개 | "
          f"기간 {s['start'][:19]} ~ {s['end'][:19]} (UTC)")
    for w in p.warnings:
        print(f"※ {w}")
    print(f"탐지: 높음 {s['levels']['높음']} / 중간 {s['levels']['중간']} / 낮음 {s['levels']['낮음']}\n")

    for ip in r["ips"]:
        g = ip["intel"].get("geo") or {}
        where = f" · {g['country_name']}" if g.get("country_name") else ""
        where += f" · AS{g['asn']} {g['org']}" if g.get("asn") else ""
        print(f"{c(ip['level'])}[{ip['level']}]{reset} {ip['ip']}{where}  ({ip['stats']['requests']:,}회 요청)")
        for f in ip["findings"]:
            print(f"    - {f['name']}: {f['reason']}")
    if not r["ips"]:
        print("탐지된 이상 행위가 없습니다.")

    if a.json:
        with open(a.json, "w", encoding="utf-8") as fp:
            json.dump(r, fp, ensure_ascii=False, indent=2)
        print(f"\nJSON 저장: {a.json}")
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8-sig") as fp:
            w = csv.writer(fp)
            w.writerow(["ip", "위험도", "탐지 유형", "탐지 사유", "요청 수", "AI 점수"])
            for ip in r["ips"]:
                w.writerow([ip["ip"], ip["level"],
                            " / ".join(f["name"] for f in ip["findings"]),
                            " / ".join(f["reason"] for f in ip["findings"]),
                            ip["stats"]["requests"], ip["ml_score"]])
        print(f"CSV 저장: {a.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
