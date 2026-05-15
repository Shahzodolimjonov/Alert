import os
import hashlib
import hmac
import time
import json
import html
from datetime import datetime, timedelta
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from models import WebhookResponse, QRadarOffense, QRadarEvent
from config import settings

RATE_LIMIT_WINDOW = 60

os.makedirs("logs", exist_ok=True)
os.makedirs("data", exist_ok=True)

logger.add("logs/webhook.log", rotation="10 MB", retention="30 days", level="INFO")
logger.add("logs/security.log", rotation="10 MB", retention="90 days", level="WARNING")
logger.add("logs/errors.log", rotation="10 MB", retention="30 days", level="ERROR")

rate_limit_store: dict = defaultdict(list)
processed_offenses: dict = {}
failed_auth_attempts: dict = defaultdict(list)
security = HTTPBearer(auto_error=False)


def validate_config():
    if not settings.TELEGRAM_TOKEN or settings.TELEGRAM_TOKEN == "your_telegram_bot_token":
        raise ValueError("TELEGRAM_TOKEN is required")
    if not settings.CHAT_ID or settings.CHAT_ID == "your_chat_id":
        raise ValueError("CHAT_ID is required")
    if not settings.WEBHOOK_SECRET or settings.WEBHOOK_SECRET == "mysecret123":
        logger.warning("Using default WEBHOOK_SECRET - change in production!")


def verify_hmac_signature(payload: bytes, signature: str) -> bool:
    if not settings.WEBHOOK_SECRET or not signature:
        return True
    expected = hmac.new(
        settings.WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    rate_limit_store[client_ip] = [
        t for t in rate_limit_store[client_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]
    if len(rate_limit_store[client_ip]) >= settings.MAX_REQUESTS_PER_MINUTE:
        logger.warning(f"Rate limit exceeded: {client_ip}")
        return False
    rate_limit_store[client_ip].append(now)
    return True


def check_ip_whitelist(client_ip: str) -> bool:
    if not settings.allowed_ips_list:
        return True
    return client_ip in settings.allowed_ips_list


def log_auth_failure(client_ip: str, reason: str):
    failed_auth_attempts[client_ip].append(time.time())
    logger.warning(f"Auth failure from {client_ip}: {reason}")
    
    recent = [t for t in failed_auth_attempts[client_ip] if time.time() - t < 300]
    if len(recent) >= 5:
        logger.critical(f"Multiple auth failures from {client_ip} - possible attack!")


def save_audit_log(event_type: str, data: dict, status: str, client_ip: str):
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "client_ip": client_ip,
        "status": status,
        "data_keys": list(data.keys()) if isinstance(data, dict) else None
    }
    try:
        with open(f"data/audit_{datetime.now().strftime('%Y%m')}.jsonl", "a") as f:
            f.write(json.dumps(audit_entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to save audit log: {e}")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def send_telegram(message: str) -> bool:
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/sendMessage"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(url, json={
                "chat_id": settings.CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            })
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Telegram error: {e}")
            raise  # Let tenacity retry


def format_offense_alert(data: QRadarOffense) -> str:
    severity_val = data.severity if data.severity is not None else 5
    severity_emoji = {
        1: "🟢", 2: "🟡", 3: "🟡", 4: "🟠", 5: "🟠",
        6: "🔴", 7: "🔴", 8: "🔴", 9: "🔴", 10: "🚨"
    }.get(severity_val, "⚠️")
    
    severity_text = {
        1: "Low", 2: "Low-Medium", 3: "Medium", 4: "Medium",
        5: "Medium-High", 6: "High", 7: "High",
        8: "Critical", 9: "Critical", 10: "Critical"
    }.get(severity_val, "Unknown")
    
    desc = str(data.description or 'No description')[:200]
    desc = html.escape(desc)
    
    return f"""
{severity_emoji} <b>QRadar ALERT</b>

🏷 <b>Offense ID:</b> <code>{html.escape(str(data.id or 'N/A'))}</code>
📝 <b>Description:</b> {desc}
⚡ <b>Severity:</b> {severity_text} ({severity_val}/10)
🔖 <b>Status:</b> {html.escape(str(data.status or 'UNKNOWN'))}
🌐 <b>Source IPs:</b> <code>{html.escape(str(data.source_address_ids or 'N/A'))}</code>
🎯 <b>Dest IPs:</b> <code>{html.escape(str(data.destination_address_ids or 'N/A'))}</code>
📊 <b>Events:</b> {html.escape(str(data.event_count or 'N/A'))}
🔢 <b>Flows:</b> {html.escape(str(data.flow_count or 'N/A'))}
👤 <b>Assigned:</b> {html.escape(str(data.assigned_to or 'Unassigned'))}
⏰ <b>Time:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
"""


def format_event_alert(data: QRadarEvent) -> str:
    magnitude_val = data.magnitude if data.magnitude is not None else 3
    magnitude_emoji = {
        1: "🟢", 2: "🟡", 3: "🟡", 4: "🟠", 5: "🟠",
        6: "🔴", 7: "🔴", 8: "🔴"
    }.get(magnitude_val, "⚠️")
    
    # Firewall eventligini aniqlash
    is_firewall = any([data.rule_name, data.rule_action, data.src, data.product])
    
    if is_firewall:
        product_str = html.escape(str(data.product or 'Firewall'))
        
        # Action ga qarab emoji qo'yish
        action_str = str(data.rule_action or '').lower()
        if action_str in ["drop", "block", "deny", "reject"]:
            action_emoji = "⛔"
        elif action_str in ["accept", "allow", "permit"]:
            action_emoji = "✅"
        else:
            action_emoji = "⚠️"
            
        return f"""
{magnitude_emoji} <b>{product_str} EVENT</b>

🛡️ <b>Rule Name:</b> {html.escape(str(data.rule_name or 'N/A'))}
⚡ <b>Action:</b> {action_emoji} {html.escape(str(data.rule_action or 'N/A'))}
🌐 <b>Source:</b> <code>{html.escape(str(data.src or data.sourceip or 'N/A'))}:{html.escape(str(data.s_port or 'N/A'))}</code>
🎯 <b>Destination:</b> <code>{html.escape(str(data.destinationip or data.xlatedst or 'N/A'))}:{html.escape(str(data.xlatedport or 'N/A'))}</code>
🔌 <b>Protocol/Service:</b> {html.escape(str(data.proto or 'N/A'))} / {html.escape(str(data.service or 'N/A'))}
👤 <b>User:</b> {html.escape(str(data.username or 'Unknown'))}
📋 <b>Event:</b> {html.escape(str(data.eventname or 'Unknown'))}
🕐 <b>Time:</b> {html.escape(str(data.starttime or 'N/A'))}
"""
    else:
        return f"""
{magnitude_emoji} <b>QRadar EVENT</b>

👤 <b>User:</b> {html.escape(str(data.username or 'Unknown'))}
🌐 <b>Source IP:</b> <code>{html.escape(str(data.sourceip or 'N/A'))}</code>
🎯 <b>Dest IP:</b> <code>{html.escape(str(data.destinationip or 'N/A'))}</code>
📋 <b>Event:</b> {html.escape(str(data.eventname or 'Unknown'))}
🕐 <b>Time:</b> {html.escape(str(data.starttime or 'N/A'))}
⚡ <b>Magnitude:</b> {magnitude_val}/10
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 QRadar Webhook Server starting...")
    try:
        validate_config()
        logger.info("✅ Configuration validated")
    except ValueError as e:
        logger.error(f"❌ Configuration error: {e}")
    
    yield
    
    logger.info("🛑 QRadar Webhook Server shutting down...")
    rate_limit_store.clear()


app = FastAPI(
    title="QRadar Telegram Bot",
    description="Secure webhook server for QRadar alerts",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def verify_auth(x_secret: Optional[str] = Header(default=None, alias="X-Secret")):
    if not x_secret or x_secret != settings.WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid credentials")
    return True


def verify_admin(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not settings.ADMIN_API_KEY:
        return True
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Admin auth required")
    if not hmac.compare_digest(credentials.credentials, settings.ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin key")
    return True


@app.get("/")
async def root():
    return {"status": "online", "service": "QRadar Telegram Bot", "version": "1.0.0"}


@app.get("/health")
async def health_check(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")
    
    return {
        "status": "healthy",
        "telegram_configured": bool(settings.TELEGRAM_TOKEN and settings.TELEGRAM_TOKEN != "your_telegram_bot_token"),
        "security": {
            "rate_limiting": True,
            "ip_whitelist": bool(settings.allowed_ips_list),
            "audit_logging": True
        }
    }


@app.post("/webhook/qradar", response_model=WebhookResponse)
async def qradar_webhook(
    request: Request,
    data: QRadarOffense,
    x_secret: Optional[str] = Header(default=None, alias="X-Secret"),
    x_signature: Optional[str] = Header(default=None, alias="X-Signature")
):
    client_ip = request.client.host if request.client else "unknown"
    
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    if not check_ip_whitelist(client_ip):
        logger.warning(f"IP not in whitelist: {client_ip}")
        raise HTTPException(status_code=403, detail="IP not allowed")
    
    if not x_secret or x_secret != settings.WEBHOOK_SECRET:
        log_auth_failure(client_ip, "Invalid secret")
        raise HTTPException(status_code=403, detail="Forbidden")
    
    raw_body = await request.body()
    
    if x_signature and not verify_hmac_signature(raw_body, x_signature):
        logger.warning(f"Invalid HMAC from {client_ip}")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    offense_id = data.id
    if offense_id:
        oid = str(offense_id)
        if oid in processed_offenses:
            last_time = processed_offenses[oid]
            if datetime.utcnow() - last_time < timedelta(hours=24):
                return WebhookResponse(status="duplicate", message="Already processed")
        processed_offenses[oid] = datetime.utcnow()
        if len(processed_offenses) > 10000:
            processed_offenses.clear()
    
    message = format_offense_alert(data)
    
    try:
        await send_telegram(message)
        success = True
    except Exception:
        success = False
    
    save_audit_log("offense", data.model_dump(), "ok" if success else "failed", client_ip)
    
    if success:
        return WebhookResponse(status="ok", message="Alert sent")
    return WebhookResponse(status="error", message="Failed to send")


@app.post("/webhook/qradar/event", response_model=WebhookResponse)
async def qradar_event_webhook(
    request: Request,
    data: QRadarEvent,
    x_secret: Optional[str] = Header(default=None, alias="X-Secret")
):
    client_ip = request.client.host if request.client else "unknown"
    
    if not check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    if not x_secret or x_secret != settings.WEBHOOK_SECRET:
        log_auth_failure(client_ip, "Invalid secret")
        raise HTTPException(status_code=403, detail="Forbidden")
    
    message = format_event_alert(data)
    
    try:
        await send_telegram(message)
        success = True
    except Exception:
        success = False
    
    save_audit_log("event", data.model_dump(), "ok" if success else "failed", client_ip)
    
    if success:
        return WebhookResponse(status="ok", message="Event sent")
    return WebhookResponse(status="error", message="Failed to send")


@app.post("/test/telegram")
async def test_telegram(verify_auth: bool = Depends(verify_auth)):
    message = f"""
🧪 <b>Test Message</b>

✅ QRadar Telegram Bot working!
🔒 Security: Enabled
🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
"""
    try:
        await send_telegram(message)
        success = True
    except Exception:
        success = False
    
    if success:
        return WebhookResponse(status="ok", message="Test sent")
    return WebhookResponse(status="error", message="Failed")


@app.get("/admin/stats")
async def admin_stats(admin: bool = Depends(verify_admin)):
    return {
        "processed_offenses": len(processed_offenses),
        "rate_limit_entries": len(rate_limit_store),
        "failed_auth_total": sum(len(v) for v in failed_auth_attempts.values())
    }


@app.get("/admin/logs")
async def admin_logs(lines: int = 100, admin: bool = Depends(verify_admin)):
    try:
        with open("logs/webhook.log", "r") as f:
            all_lines = f.readlines()
            return {"logs": all_lines[-lines:]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/clear-offenses")
async def clear_offenses(admin: bool = Depends(verify_admin)):
    count = len(processed_offenses)
    processed_offenses.clear()
    return {"status": "ok", "cleared": count}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers={"WWW-Authenticate": "Bearer"}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal error"})


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info",
        access_log=False
    )
