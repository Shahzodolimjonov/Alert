# QRadar → Telegram Alert Bot

## Arxitektura

```
QRadar (Offense / Rule Trigger)
        ↓ HTTP POST webhook
FastAPI Server (/webhook/qradar)
        ↓
Telegram Bot API
        ↓
User / Group
```

## Xavfsizlik xususiyatlari

| Xususiyat | Description |
|------------|-------------|
| **Rate Limiting** | Har bir IP dan 1 daqiqada 100 ta so'rov |
| **IP Whitelist** | Faqat ruxsat berilgan IP lar dan kirish |
| **Secret Auth** | X-Secret header bilan autentifikatsiya |
| **HMAC Signature** | Payload imzo tekshirish |
| **Input Sanitization** | XSS va injection himoyasi |
| **Audit Logging** | Barcha so'rovlar JSONL formatda |
| **Security Headers** | X-Frame-Options, CSP, HSTS |
| **Deduplication** | Bir xil offense takrorlanmasligi |

## O'rnatish

```bash
pip install -r requirements.txt
cp .env.example .env
nano .env
python main.py
```

## .env sozlamalari

```env
TELEGRAM_TOKEN=123456:ABC-xyz...
CHAT_ID=123456789

WEBHOOK_SECRET=strong_random_secret_here
ADMIN_API_KEY=strong_admin_key_here

ALLOWED_IPS=192.168.1.100,10.0.0.50

MAX_REQUESTS_PER_MINUTE=100
```

## Telegram Bot yaratish

1. Telegramda @BotFather ga yozing
2. `/newbot` buyrug'ini bering
3. Bot nomi va username bering
4. TOKEN ni saqlang

## Chat ID olish

1. Botga birinchi xabarni yozing
2. Brauzerda oching:
```
https://api.telegram.org/bot<TOKEN>/getUpdates
```
3. JSON dan `"chat": {"id": ...}` ni oling

## QRadar webhook sozlamasi

```
Action: Send HTTP Request

URL: https://your-domain.com/webhook/qradar
Method: POST
Headers:
  Content-Type: application/json
  X-Secret: your_webhook_secret
```

Body (JSON):
```json
{
  "id": ${offense_id},
  "description": "${offense_description}",
  "severity": ${offense_severity},
  "status": "${offense_status}",
  "source_address_ids": "${source_address_ids}",
  "destination_address_ids": "${destination_address_ids}",
  "event_count": ${event_count},
  "flow_count": ${flow_count}
}
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | - | Service info |
| GET | `/health` | - | Health check |
| POST | `/webhook/qradar` | X-Secret | Offense webhook |
| POST | `/webhook/qradar/event` | X-Secret | Event webhook |
| POST | `/test/telegram` | X-Secret | Test xabar |
| GET | `/admin/stats` | Bearer | Statistika |
| GET | `/admin/logs` | Bearer | Loglar |

## Test qilish

```bash
# Health check
curl http://localhost:8000/health

# Telegram test
curl -X POST http://localhost:8000/test/telegram \
  -H "X-Secret: your_secret"

# Manual webhook
curl -X POST http://localhost:8000/webhook/qradar \
  -H "Content-Type: application/json" \
  -H "X-Secret: your_secret" \
  -H "X-Signature: <hmac_sha256>" \
  -d '{"id": 123, "description": "Test", "severity": 8}'
```

## Security Logs

Log fayllari:
- `logs/webhook.log` - Umumiy loglar
- `logs/security.log` - Xavfsizlik voqealari
- `logs/errors.log` - Xatolar
- `data/audit_YYYYMM.jsonl` - Audit log

## Production tavsiyalar

1. **SSL** - Har doim HTTPS ishlatilsin
2. **Firewall** - Faqat QRadar IP dan kirishga ruxsat
3. **Strong secrets** - WEBHOOK_SECRET va ADMIN_API_KEY ni o'zgartiring
4. **Environment** - .env faylini gitignore ga qo'shing
5. **Backup** - Audit loglarni zaxiralash

## Xavfsizlik sozlamalari

```env
# IP whitelist (vergul bilan ajratilgan)
ALLOWED_IPS=192.168.1.100,10.0.0.50

# Rate limiting (1 daqiqada)
MAX_REQUESTS_PER_MINUTE=100

# Admin API key (admin endpoints uchun)
ADMIN_API_KEY=very_strong_key_here
```

## Xatolarni tuzatish

| Muammo | Yechim |
|--------|--------|
| 403 Forbidden | X-Secret noto'g'ri |
| 401 Invalid signature | HMAC signature tekshiring |
| 429 Rate limit | IP whitelist yoki kutish |
| IP not allowed | ALLOWED_IPS ga qo'shing |
