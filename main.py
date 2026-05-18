import os
import json
import html
import asyncio
from datetime import datetime
from loguru import logger
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from models import QRadarOffense, QRadarEvent
from config import settings

os.makedirs("logs", exist_ok=True)
os.makedirs("data", exist_ok=True)

logger.add("logs/webhook.log", rotation="10 MB", retention="30 days", level="INFO")
logger.add("logs/errors.log", rotation="10 MB", retention="30 days", level="ERROR")

def validate_config():
    if not settings.TELEGRAM_TOKEN or settings.TELEGRAM_TOKEN == "your_telegram_bot_token":
        raise ValueError("TELEGRAM_TOKEN is required")
    if not settings.CHAT_ID or settings.CHAT_ID == "your_chat_id":
        raise ValueError("CHAT_ID is required")

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
            raise

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
    
    is_firewall = any([data.rule_name, data.rule_action, data.src, data.product])
    
    if is_firewall:
        product_str = html.escape(str(data.product or 'Firewall'))
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

async def process_json_payload(payload: dict):
    try:
        # Determine if payload is Offense or Event based on specific keys
        if "severity" in payload or "offense_type" in payload or "source_address_ids" in payload:
            offense_data = QRadarOffense(**payload)
            msg = format_offense_alert(offense_data)
        else:
            event_data = QRadarEvent(**payload)
            msg = format_event_alert(event_data)
        
        await send_telegram(msg)
        logger.info("Successfully processed and sent alert to Telegram.")
    except Exception as e:
        logger.error(f"Error processing payload: {e}\nPayload: {payload}")

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info('peername')
    logger.info(f"New connection from {addr}")
    
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            
            line = data.decode('utf-8', errors='replace').strip()
            if not line:
                continue
                
            logger.info(f"Received raw data length: {len(line)}")
            
            try:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    await process_json_payload(payload)
                else:
                    logger.warning(f"Payload is not a JSON dict: {line[:200]}")
            except json.JSONDecodeError:
                # Sometimes Syslog prefixes the JSON. Let's try to extract JSON.
                try:
                    start_idx = line.find('{')
                    end_idx = line.rfind('}')
                    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                        json_str = line[start_idx:end_idx+1]
                        payload = json.loads(json_str)
                        if isinstance(payload, dict):
                            await process_json_payload(payload)
                        else:
                            logger.warning(f"Extracted payload is not a JSON dict: {json_str[:200]}")
                    else:
                        logger.error(f"Invalid JSON received from {addr}: {line[:200]}...")
                except Exception as ex:
                    logger.error(f"Failed to extract JSON from {addr}: {line[:200]}... Error: {ex}")
                
    except ConnectionResetError:
        logger.warning(f"Connection reset by {addr}")
    except Exception as e:
        logger.error(f"Error handling connection from {addr}: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"Connection closed for {addr}")

async def main():
    try:
        validate_config()
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        return

    host = settings.HOST
    port = settings.PORT
    
    server = await asyncio.start_server(handle_client, host, port)
    
    addr = server.sockets[0].getsockname()
    logger.info(f"🚀 QRadar TCP Syslog/JSON Server listening on {addr[0]}:{addr[1]}")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
