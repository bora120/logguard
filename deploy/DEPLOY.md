# 배포 가이드

LogGuard는 두 가지 방법으로 배포할 수 있습니다.

| 방법 | 장점 | 제한 |
|---|---|---|
| **A. Vercel** (가장 쉬움) | GitHub 연결만 하면 자동 배포, `*.vercel.app` 주소와 HTTPS 자동 | 업로드는 브라우저 압축 후 4MB까지(원본 로그 기준 보통 수십 MB), 무료 Hobby 요금제는 비상업적 용도만 |
| **B. VPS + Docker** | 제한 없음 (기본 50MB), 완전한 제어 | 서버를 직접 관리 |

---

## A. Vercel 배포

이 저장소에는 Vercel 설정(`pyproject.toml`의 `[tool.vercel]`, `vercel.json`, `.python-version`)이 들어 있어 추가 설정 없이 배포됩니다.

1. GitHub에 저장소를 올립니다. 제목 글꼴(온글잎 콘콘체)은 파일 재배포가 허용되지 않으므로 저장소를 **비공개(Private)**로 두세요. (GitHub → 저장소 → Settings → General → Danger Zone → Change visibility) Vercel은 비공개 저장소도 연결할 수 있어요.
2. https://vercel.com 에서 **Continue with GitHub** 로 가입·로그인합니다.
3. **Add New… → Project** → `logguard` 저장소 옆 **Import**
4. Framework Preset 이 **FastAPI** 로 잡혔는지 확인합니다. (Build/Output 설정은 비워둡니다)
5. (선택) **Environment Variables** 에 추가
   - `CONTACT_EMAIL`: 화면 하단 문의처
   - `ABUSEIPDB_KEY`: AbuseIPDB 무료 API 키
6. **Deploy** → 1~3분 뒤 `https://logguard-xxxx.vercel.app` 주소가 생깁니다.

이후에는 GitHub에 `git push` 할 때마다 자동으로 다시 배포됩니다.

### Vercel에서 달라지는 점
- Vercel은 `VERCEL` 환경변수를 자동으로 넣어주고, LogGuard는 이를 보고 업로드 제한을 **압축 후 4MB**로 맞춥니다. (Vercel 함수 요청 본문 제한 4.5MB)
- 브라우저가 업로드 직전에 로그를 gzip으로 압축하므로 원본 기준으로는 훨씬 큰 로그도 올라갑니다. 압축 후에도 4MB를 넘으면 업로드 전에 안내 문구가 뜹니다.
- 요청 횟수 제한은 함수 인스턴스마다 따로 세므로 대략적인 보호만 됩니다. 남용이 걱정되면 Vercel의 Firewall(WAF) 규칙으로 `/analyze` 에 Rate Limit 을 거세요.
- 실행 시간 제한은 `vercel.json` 에서 60초로 잡았습니다.

### 빌드가 실패하면
- **번들 크기 초과**: Python 함수는 압축 해제 기준 500MB까지입니다. `vercel.json` 의 `excludeFiles` 에 필요 없는 폴더를 더 넣으세요.
- **`PYTHON_ENTRYPOINT_NOT_FOUND`**: `pyproject.toml` 의 `[tool.vercel] entrypoint = "app.main:app"` 가 있는지 확인하세요.
- Vercel 대시보드 → Deployments → 실패한 배포 → **Build Logs** 내용을 확인하세요.

---

## B. VPS + Docker 배포 (Ubuntu + 도메인 + HTTPS)

준비물: 공인 IP가 있는 Ubuntu 22.04/24.04 서버(VPS), 도메인 1개.
아래에서 `example.com` 은 내 도메인으로 바꿉니다.

## 1. 도메인 연결
도메인 관리 페이지에서 **A 레코드**를 추가합니다.
- 호스트: `@` (또는 `logguard` 같은 서브도메인)
- 값: VPS 공인 IP

`ping example.com` 으로 VPS IP가 나오면 연결된 것입니다. (반영까지 몇 분~몇 시간)

## 2. 서버 기본 설정
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx git
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

## 3. Docker 설치
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```
로그아웃 후 다시 로그인하고 `docker ps` 가 sudo 없이 실행되는지 확인합니다.

## 4. 앱 올리고 실행
```bash
# GitHub에 올렸다면
git clone https://github.com/내아이디/logguard.git
cd logguard
# (또는 scp로 logguard 폴더를 복사)

docker compose up -d --build
curl http://127.0.0.1:8000/healthz      # {"ok":true}
```
`docker-compose.yml` 에서 바꿀 만한 값:
- `CONTACT_EMAIL`: 화면 하단에 표시할 문의 메일
- `ABUSEIPDB_KEY`: [AbuseIPDB](https://www.abuseipdb.com) 가입 후 발급한 무료 API 키 (하루 1,000회 조회). 넣으면 업로드 화면에 평판 조회 선택지가 나타납니다.

국가·통신사 데이터(DB-IP Lite)는 매월 갱신됩니다. 한 달에 한 번 정도 아래를 실행한 뒤 다시 빌드하세요.
```bash
python3 tools/update_geoip.py && docker compose up -d --build
```

## 5. Nginx 연결
```bash
sudo cp deploy/nginx-logguard.conf /etc/nginx/sites-available/logguard
sudo sed -i 's/example.com/내도메인/' /etc/nginx/sites-available/logguard
sudo ln -s /etc/nginx/sites-available/logguard /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```
이제 `http://내도메인` 으로 접속됩니다.

## 6. HTTPS 인증서 (Let's Encrypt, 무료)
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d 내도메인
```
이메일 입력, 약관 동의, HTTP→HTTPS 리다이렉트 선택을 하면 끝입니다. 인증서는 자동 갱신됩니다.
(`sudo certbot renew --dry-run` 으로 갱신 테스트)

## 7. 업데이트
```bash
cd logguard
git pull
docker compose up -d --build
```

## 8. 운영 점검
- 앱 로그 보기: `docker compose logs -f --tail 100`
- 메모리: 큰 로그(수백만 줄)를 분석하면 1GB 이상 쓸 수 있습니다. VPS 메모리가 1GB라면 `MAX_UPLOAD_MB` 와 `MAX_LINES` 를 낮추고 `MAX_CONCURRENT=1` 로 두세요.
- 요청 제한: 앱 자체 제한은 워커별로 따로 세므로, 실제 제한은 Nginx의 `limit_req` 가 담당합니다.
- 내 서비스의 Nginx 로그(`/var/log/nginx/access.log`)를 LogGuard로 분석해 보는 것도 좋은 시연이 됩니다.

## Docker 없이 실행하고 싶다면 (systemd)
```bash
cd ~/logguard && python3 -m venv venv && venv/bin/pip install -r requirements.txt
sudo tee /etc/systemd/system/logguard.service >/dev/null <<EOF
[Unit]
Description=LogGuard
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/logguard
ExecStart=$HOME/logguard/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --proxy-headers
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now logguard
```
