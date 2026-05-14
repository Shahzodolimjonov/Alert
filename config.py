from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    TELEGRAM_TOKEN: str
    CHAT_ID: str
    
    WEBHOOK_SECRET: str = "mysecret123"
    ADMIN_API_KEY: str = ""
    ENCRYPTION_KEY: str = ""
    
    ALLOWED_IPS: str = ""
    MAX_REQUESTS_PER_MINUTE: int = 100
    
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def allowed_ips_list(self) -> List[str]:
        if not self.ALLOWED_IPS:
            return []
        return [ip.strip() for ip in self.ALLOWED_IPS.split(",") if ip.strip()]

settings = Settings()
