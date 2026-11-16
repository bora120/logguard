# LogGuard — 웹 서버 로그 이상 행위 탐지

Apache·Nginx 접속 로그를 올리면 **규칙 기반 탐지 + AI(Isolation Forest)** 로 공격 의심 IP를 찾고,
위험도·탐지 이유·대응 방법을 보고서로 보여주는 웹 서비스입니다.

- 지원 형식: Apache/Nginx **Combined**, **Common**, **Nginx main(+X-Forwarded-For)** 자동 감지, **사용자 지정 LogFormat/log_format**, `.gz` 압축 파일
- CDN·프록시 뒤 서버는 **X-Forwarded-For의 실제 접속자 IP**로 분석
- **세션(시간 구간) 단위 AI 분석**: 평소엔 정상인 IP가 특정 시간대에만 공격해도 그 구간을 찾아냄
- **위협 정보**: 국가·통신사(ASN), 데이터센터 IP 표시, 검색봇 진위 확인(역방향 DNS), AbuseIPDB 평판 조회(선택)
- **공격 타임라인**: 탐지된 IP별 의심 구간을 한눈에
- 업로드한 로그는 **디스크에 저장하지 않고** 분석 직후 폐기
- 서버 밖으로 로그를 보내기 싫다면 **CLI 버전**으로 서버 안에서 바로 분석 가능

## 탐지 방식

| 구분 | 이름 | 기준 |
|---|---|---|
| R1 | 과도한 요청 | 60초 안에 100회 이상 (300회 이상이면 위험 높음), 검증된 검색엔진 봇 제외 |
| R2 | 경로 스캔 | 404 응답 10회 이상 |
| R3 | 민감 경로 접근 | `.env`, `.git`, `wp-admin`, `phpmyadmin`, 백업 파일 등 |
| R4 | 공격 도구 사용 | User-Agent에 sqlmap, nikto, nuclei, wpscan 등 |
| R5 | 공격 패턴 | SQL 인젝션, XSS, 경로 조작, Log4Shell 등 (정상 응답이면 우선 점검 표시) |
| R6 | 무차별 대입 의심 | 60초 안에 로그인 경로 20회 이상 |
| R7 | 검색봇 사칭 | Googlebot·Bingbot·Yeti 등을 자칭하지만 역방향 DNS 검증 실패 |
| AI | AI 이상 행위 | 세션별 행동 특징 9가지를 다른 세션과 비교해 동떨어진 구간 탐지 |
| TI | 알려진 악성 IP | AbuseIPDB 신고 신뢰도 50% 이상 (선택 기능) |

- **세션**: 같은 IP라도 30분 이상 쉬었다 다시 오면 새 세션으로 나눕니다.
- AI는 정답 라벨 없이 학습하는 **비지도 학습**(Isolation Forest)이라 처음 보는 서버의 로그에도 그 자리에서 적용됩니다.
- AI가 특이하다고 본 세션 중 **공격 쪽으로 특이하고 근거가 충분한 경우만** 남깁니다. (예: 로그인 요청 10회 이상이면서 비율 50% 이상) 정상 사용자 300명 로그에서 오탐률 5% 미만을 테스트로 확인합니다.
- 접속 IP가 10개 미만이면 비교 대상이 부족해 AI 분석은 생략합니다.

## 폴더 구조

```
logguard/
├── app/
│   ├── main.py            # 웹 서버 (FastAPI)
│   ├── cli.py             # 명령줄 버전
│   ├── config.py          # 환경변수 설정
│   ├── engine/
│   │   ├── parser.py      # 로그 파싱 (형식 자동 감지, 사용자 지정 형식, X-Forwarded-For, gz)
│   │   ├── analyzer.py    # 요청 표시, 세션 분할, 규칙, AI, 보고서 생성
│   │   └── intel.py       # 국가·ASN, 검색봇 검증, AbuseIPDB
│   ├── data/              # DB-IP Lite 국가·ASN 데이터 (CC BY 4.0)
│   ├── templates/         # 화면 (Jinja2, 자동 이스케이프)
│   ├── static/            # CSS, JS, Chart.js (CDN 없이 자체 제공)
│   └── sample/            # 체험용 샘플 로그 (가상 트래픽, 문서용 IP 대역 사용)
├── tools/                 # 성능 평가, GeoIP 갱신 스크립트
├── tests/                 # pytest
├── deploy/                # Nginx 설정, 배포 가이드
├── Dockerfile
└── docker-compose.yml
```

## 내 PC(또는 Ubuntu VM)에서 실행

```bash
cd logguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
브라우저에서 `http://서버IP:8000` 으로 접속합니다.

## CLI로 분석 (로그를 외부로 보내지 않음)

```bash
python -m app.cli /var/log/apache2/access.log
python -m app.cli access.log.gz --csv result.csv --json result.json
python -m app.cli access.log --log-format '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D'
python -m app.cli access.log --ip-source xff --abuseipdb-key 내키
```

## 탐지 성능 평가

정답 라벨(ip,label)이 있는 로그로 정밀도·재현율을 계산합니다.
```bash
python tools/evaluate.py app/sample/sample_access.log tests/sample_labels.csv
```

## 국가·통신사 데이터 갱신

`app/data/` 에 DB-IP Lite(CC BY 4.0) 데이터가 들어 있습니다. 매월 갱신되므로 가끔 아래를 실행하세요.
```bash
python tools/update_geoip.py
```

## 테스트

```bash
pytest -q
```

## 설정 (환경변수)

| 이름 | 기본값 | 설명 |
|---|---|---|
| `MAX_UPLOAD_MB` | 50 | 업로드 파일 최대 크기 |
| `MAX_DECOMPRESSED_MB` | 300 | 압축을 푼 뒤 최대 크기 (압축 폭탄 방지) |
| `MAX_LINES` | 2000000 | 최대 줄 수 |
| `RATE_LIMIT_COUNT` / `RATE_LIMIT_WINDOW` | 10 / 600 | IP당 분석 횟수 제한 (10분에 10회) |
| `MAX_CONCURRENT` | 2 | 동시에 실행하는 분석 수 |
| `CONTACT_EMAIL` | (없음) | 화면 하단에 표시할 문의처 |
| `VERIFY_BOTS` | 1 | 검색봇 역방향 DNS 검증 (DNS가 안 되는 서버에서는 자동으로 건너뜀) |
| `ABUSEIPDB_KEY` | (없음) | AbuseIPDB API 키. 넣으면 업로드 화면에 평판 조회 선택지가 나타남 (무료 1,000회/일) |
| `ABUSEIPDB_MAX` | 20 | 분석 1회당 평판 조회할 최대 IP 수 |
| `GEOIP_COUNTRY_DB` / `GEOIP_ASN_DB` | app/data/*.mmdb | 국가·ASN 데이터 파일 경로 |

## 보안 설계

- 업로드 로그는 메모리에서만 처리하고 즉시 폐기, 결과도 서버에 저장하지 않음 (CSV는 브라우저에서 생성)
- 로그 속 공격 문자열(`<script>` 등)은 Jinja2 자동 이스케이프로 출력 → XSS 방지
- CSP(`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, `no-referrer` 등 보안 헤더 적용
- 업로드 크기, 압축 해제 크기, 줄 수 제한 / 분석 동시 실행 수 제한 / IP당 요청 횟수 제한
- CSV 내보내기 시 엑셀 수식 주입(`=`, `+`, `-`, `@`로 시작) 방지
- Docker 컨테이너는 일반 사용자 권한, 읽기 전용 파일시스템으로 실행

## 알려진 한계

- 여러 사용자가 IP 하나를 공유하는 환경(회사, 학교)은 한 명처럼 보일 수 있습니다.
- 로그에 X-Forwarded-For가 기록되지 않는 CDN 환경은 실제 접속자 IP를 알 수 없습니다.
- 검색봇 검증은 DNS가 동작하는 서버에서만 수행됩니다. DNS 장애 시에는 '미검증'으로 두고 과도한 요청 규칙에서만 제외합니다.
- 사용자 지정 형식의 `%{...}t`(시간 형식 변경)는 지원하지 않습니다.
- DB-IP Lite는 무료판이라 국가·ASN 정확도가 상용판보다 낮습니다.
