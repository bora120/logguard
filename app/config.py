import os

APP_NAME = os.getenv("APP_NAME", "LogGuard")
ON_VERCEL = bool(os.getenv("VERCEL"))                            # Vercel 이 자동으로 넣어주는 환경변수
# Vercel 함수는 요청 본문이 4.5MB로 제한된다. 브라우저가 gzip으로 압축해서 보내므로 원본 기준으로는 보통 수십 MB까지 가능.
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "4" if ON_VERCEL else "50"))   # 업로드(압축 후) 크기
MAX_DECOMPRESSED_MB = int(os.getenv("MAX_DECOMPRESSED_MB", "300"))  # 압축 푼 뒤 크기
MAX_LINES = int(os.getenv("MAX_LINES", "2000000"))
RATE_LIMIT_COUNT = int(os.getenv("RATE_LIMIT_COUNT", "10"))      # IP당 분석 횟수
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "600"))   # 초
MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT", "2"))           # 동시에 돌리는 분석 수
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "")
VERIFY_BOTS = os.getenv("VERIFY_BOTS", "1") == "1"                # 검색봇 역방향 DNS 검증
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")                     # 비워두면 평판 조회 기능 숨김
ABUSEIPDB_MAX = int(os.getenv("ABUSEIPDB_MAX", "20"))             # 분석 1회당 조회할 최대 IP 수
MAX_FORMAT_LEN = 500
DISPLAY_TZ = os.getenv("DISPLAY_TZ", "Asia/Seoul")                # 보고서에 표시할 시간대
