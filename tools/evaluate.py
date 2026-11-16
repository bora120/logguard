"""
탐지 성능 평가 도구 — 정답 라벨이 있는 로그로 정밀도·재현율을 계산한다.

    python tools/evaluate.py 로그파일 라벨.csv
    python tools/evaluate.py data/access.log data/labels.csv --min-level 중간

라벨 CSV 형식: ip,label[,scenario]   (label 은 attack 또는 normal)
"""
import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import LEVEL_ORDER, analyze  # noqa: E402
from app.engine.parser import parse_path  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("labels")
    ap.add_argument("--min-level", default="낮음", choices=list(LEVEL_ORDER))
    ap.add_argument("--log-format", default=None)
    a = ap.parse_args(argv)

    p = parse_path(a.log, log_format=a.log_format)
    r = analyze(p.df, p.fmt, max_ip_reports=10**9)
    with open(a.labels, encoding="utf-8-sig") as fp:
        rows = list(csv.DictReader(fp))
    labels = {x["ip"]: x for x in rows}
    th = LEVEL_ORDER[a.min_level]
    found = {x["ip"]: x for x in r["ips"] if LEVEL_ORDER[x["level"]] >= th}

    attacks = {ip for ip, x in labels.items() if x["label"] == "attack"}
    normals = {ip for ip, x in labels.items() if x["label"] != "attack"}
    tp, fp, fn = len(attacks & found.keys()), len(normals & found.keys()), len(attacks - found.keys())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    print(f"기준: 위험도 '{a.min_level}' 이상을 탐지로 간주")
    print(f"공격 {len(attacks)}개 / 정상 {len(normals)}개 / 라벨 없는 탐지 {len(found.keys() - labels.keys())}개")
    print(f"TP {tp}  FP {fp}  FN {fn}")
    print(f"정밀도 {precision:.3f}  재현율 {recall:.3f}  F1 {f1:.3f}")
    for ip in sorted(attacks - found.keys()):
        print(f"  놓침: {ip} {labels[ip].get('scenario', '')}")
    for ip in sorted(normals & found.keys()):
        print(f"  오탐: {ip} → {', '.join(f['name'] for f in found[ip]['findings'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
