import asyncio
import os
import json
import html
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from models import QRadarOffense, QRadarEvent
from config import settings

os.makedirs("logs", exist_ok=True)
os.makedirs("data", exist_ok=True)

logger.add("logs/webhook.log", rotation="10 MB", retention="30 days", level="INFO")
logger.add("logs/security.log", rotation="10 MB", retention="90 days", level="WARNING")
logger.add("logs/errors.log", rotation="10 MB", retention="30 days", level="ERROR")

RATE_LIMIT_WINDOW = 60
rate_store: dict = defaultdict(list)
offense_dedup: dict = {}
auth_failures: dict = defaultdict(list)


def check_config():
    if not settings.TELEGRAM_TOKEN or settings.TELEGRAM_TOKEN == "your_telegram_bot_token":
        raise ValueError("TELEGRAM_TOKEN is required")
    if not settings.CHAT_ID or settings.CHAT_ID == "your_chat_id":
        raise ValueError("CHAT_ID is required")


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    rate_store[ip] = [t for t in rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_store[ip]) >= settings.MAX_REQUESTS_PER_MINUTE:
        logger.warning(f"Rate limit exceeded: {ip}")
        return False
    rate_store[ip].append(now)
    return True


def check_ip_whitelist(ip: str) -> bool:
    allowed = settings.allowed_ips_list
    if not allowed:
        return True
    if ip in allowed:
        return True
    logger.warning(f"IP not whitelisted: {ip}")
    return False


def log_auth_fail(ip: str):
    now = time.time()
    auth_failures[ip].append(now)
    recent = [t for t in auth_failures[ip] if now - t < 300]
    if len(recent) >= 5:
        logger.critical(f"Possible attack from {ip} - 5+ auth failures in 5 min")
    logger.warning(f"Auth failure from {ip}")


def sanitize(data: dict) -> dict:
    clean = {}
    for k, v in data.items():
        if isinstance(v, str):
            v = "".join(c for c in v[:5000] if c.isprintable())
        clean[k] = v
    return clean


def save_audit(event: str, ip: str, status: str, keys: list = None):
    entry = {
        "ts": datetime.now().isoformat(),
        "event": event,
        "ip": ip,
        "status": status,
        "keys": keys
    }
    try:
        with open(f"data/audit_{datetime.now().strftime('%Y%m')}.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def send_telegram(message: str) -> bool:
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_TOKEN}/sendMessage"
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.post(url, json={
                "chat_id": settings.CHAT_ID,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            })
            r.raise_for_status()
            return True
        except httpx.HTTPStatusError as e:
            logger.error(f"Telegram API {e.response.status_code}: {e.response.text[:200]}")
            raise
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            raise


def format_offense(data: QRadarOffense) -> str:
    sv = data.severity if data.severity is not None else 5
    emoji = {1: "🟢", 2: "🟡", 3: "🟡", 4: "🟠", 5: "🟠",
             6: "🔴", 7: "🔴", 8: "🔴", 9: "🔴", 10: "🚨"}.get(sv, "⚠️")
    label = {1: "Low", 2: "Low-Med", 3: "Med", 4: "Med", 5: "Med-High",
             6: "High", 7: "High", 8: "Critical", 9: "Critical", 10: "Critical"}.get(sv, "Unknown")
    desc = html.escape(str(data.description or "No description")[:200])
    return f"""{emoji} <b>QRadar ALERT</b>
🏷 ID: <code>{html.escape(str(data.id or 'N/A'))}</code>
📝 {desc}
⚡ Severity: {label} ({sv}/10)
🔖 Status: {html.escape(str(data.status or 'UNKNOWN'))}
🌐 Src: <code>{html.escape(str(data.source_address_ids or 'N/A'))}</code>
🎯 Dst: <code>{html.escape(str(data.destination_address_ids or 'N/A'))}</code>
📊 Events: {data.event_count or 'N/A'} | Flows: {data.flow_count or 'N/A'}
👤 Assigned: {html.escape(str(data.assigned_to or 'Unassigned'))}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC+5"""


def format_event(data: QRadarEvent) -> str:
    mv = data.magnitude if data.magnitude is not None else 3
    emoji = {1: "🟢", 2: "🟡", 3: "🟡", 4: "🟠", 5: "🟠",
             6: "🔴", 7: "🔴", 8: "🔴"}.get(mv, "⚠️")

    if any([data.rule_name, data.rule_action, data.src, data.product]):
        action = str(data.rule_action or "").lower()
        act_emoji = "⛔" if action in ["drop", "block", "deny", "reject"] else "✅" if action in ["accept", "allow", "permit"] else "⚠️"
        return f"""{emoji} <b>{html.escape(str(data.product or 'Firewall'))}</b>
🛡️ Rule: {html.escape(str(data.rule_name or 'N/A'))}
{act_emoji} Action: {html.escape(str(data.rule_action or 'N/A'))}
🌐 {html.escape(str(data.src or data.sourceip or 'N/A'))}:{html.escape(str(data.s_port or 'N/A'))}
🎯 {html.escape(str(data.destinationip or data.xlatedst or 'N/A'))}:{html.escape(str(data.xlatedport or 'N/A'))}
🔌 {html.escape(str(data.proto or 'N/A'))} / {html.escape(str(data.service or 'N/A'))}
👤 {html.escape(str(data.username or 'Unknown'))}
📋 {html.escape(str(data.eventname or 'Unknown'))}
🕐 {html.escape(str(data.starttime or 'N/A'))}"""

    return f"""{emoji} <b>QRadar EVENT</b>
👤 User: {html.escape(str(data.username or 'Unknown'))}
🌐 Src: <code>{html.escape(str(data.sourceip or 'N/A'))}</code>
🎯 Dst: <code>{html.escape(str(data.destinationip or 'N/A'))}</code>
📋 {html.escape(str(data.eventname or 'Unknown'))}
🕐 {html.escape(str(data.starttime or 'N/A'))}
⚡ Magnitude: {mv}/10"""


async def process(payload: dict, client_ip: str):
    payload = sanitize(payload)
    
    # QRadar event loglarida qid, eventname yoki sourceip bo'ladi. 
    # Agar bular bo'lsa, bu Offense emas, balki Event (Hodisa) hisoblanadi.
    is_event = any(k in payload for k in ["qid", "eventname", "sourceip", "destinationip", "rule_name"])
    is_offense = not is_event and any(k in payload for k in ["severity", "offense_type"])

    if is_offense:
        oid = payload.get("id")
        if oid:
            key = str(oid)
            if key in offense_dedup:
                last = offense_dedup[key]
                if datetime.utcnow() - last < timedelta(hours=24):
                    logger.info(f"Dedup offense {oid}")
                    save_audit("dedup_offense", client_ip, "skipped", list(payload.keys()))
                    return
            offense_dedup[key] = datetime.utcnow()
            if len(offense_dedup) > 10000:
                offense_dedup.clear()

        try:
            obj = QRadarOffense(**payload)
            msg = format_offense(obj)
        except Exception as e:
            logger.error(f"Offense parse error: {e}")
            return
    else:
        try:
            obj = QRadarEvent(**payload)
            msg = format_event(obj)
        except Exception as e:
            logger.error(f"Event parse error: {e}")
            return

    await send_telegram(msg)
    save_audit("offense" if is_offense else "event", client_ip, "sent", list(payload.keys()))
    logger.info(f"Alert sent ({'offense' if is_offense else 'event'})")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0] if peer else "unknown"
    logger.info(f"New connection from {client_ip}")

    if not check_ip_whitelist(client_ip):
        logger.warning(f"Blocked {client_ip} - not in whitelist")
        writer.close()
        return

    buffer = ""
    try:
        while True:
            try:
                data = await reader.read(65536)
            except ConnectionResetError:
                logger.info(f"Connection reset by {client_ip}")
                break
            except Exception as e:
                logger.error(f"Read error from {client_ip}: {e}")
                break

            if not data:
                logger.info(f"Connection closed by remote peer {client_ip}")
                break

            logger.info(f"Received {len(data)} bytes from {client_ip}")
            chunk = data.decode('utf-8', errors='replace')
            buffer += chunk

            # Satrma-satr real-time qayta ishlash (\n belgisi bo'yicha ajratamiz)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                logger.info(f"Processing real-time log from {client_ip}: {line[:200]}")
                
                if not check_rate_limit(client_ip):
                    logger.warning(f"Rate limit hit: {client_ip}")
                    continue

                try:
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        await process(payload, client_ip)
                    else:
                        logger.warning(f"Not a dict: {line[:200]}")
                except json.JSONDecodeError:
                    # Agar JSON syslog wrapper ichida bo'lsa, uni ajratib olishga harakat qilamiz
                    try:
                        start = line.find('{')
                        end = line.rfind('}')
                        if start != -1 and end != -1 and end > start:
                            payload = json.loads(line[start:end+1])
                            if isinstance(payload, dict):
                                await process(payload, client_ip)
                                continue
                    except Exception:
                        pass
                    logger.warning(f"Non-JSON data from {client_ip}: {line[:300]}")

        # Agar aloqa uzilsa va buferda oxirgi ma'lumot qolgan bo'lsa
        if buffer.strip():
            line = buffer.strip()
            try:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    await process(payload, client_ip)
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Handler error {client_ip}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"Disconnected {client_ip}")


async def main():
    check_config()
    logger.info("QRadar TCP Alert Server starting...")
    logger.info(f"Whitelist: {settings.allowed_ips_list or 'ALL'}")
    logger.info(f"Rate limit: {settings.MAX_REQUESTS_PER_MINUTE}/min")

    server = await asyncio.start_server(handle_client, settings.HOST, settings.PORT)
    addr = server.sockets[0].getsockname()
    logger.info(f"Listening on {addr[0]}:{addr[1]}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal: {e}")
