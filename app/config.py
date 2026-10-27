"""
Leadline Configuration
Phase 3: Reconnaissance Engine - Configuration and request pacing settings
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "Leadline"
    APP_VERSION: str = "0.2.0"
    DEBUG: bool = False

    # Database - Phase 7: Event Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./leadline.db"

    # API Settings
    API_PREFIX: str = "/api"
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:5173"]
    # Host header allow-list. This is a DNS-rebinding defense for a local
    # tool: a malicious website must not be able to resolve its own hostname
    # to 127.0.0.1 and reach the API as a same-origin service. Add your
    # reverse-proxy hostname here if you deliberately expose Leadline.
    ALLOWED_HOSTS: list = ["localhost", "127.0.0.1", "::1", "backend", "testserver"]

    # Reconnaissance Engine - Phase 3
    # Request pacing / traffic shaping

    # User-Agent rotation. The self-identifying default is used when
    # evasion is disabled; browser-like entries are used when it is enabled.
    DEFAULT_USER_AGENT: str = "Leadline/0.2 (+https://github.com/luel-4013/Leadline)"
    USER_AGENTS: list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Leadline/0.2 (Security Scanner)",
    ]

    # Rate Limiting - Security consideration
    REQUEST_DELAY: float = 0.5  # seconds between requests
    MAX_CONCURRENT: int = 5  # maximum parallel requests
    TIMEOUT: int = 10  # request timeout in seconds
    # Hard cap on any response body we read into memory / store in SQLite.
    # Prevents a hostile or misconfigured target from exhausting the scan
    # process or bloating the event database.
    MAX_RESPONSE_BYTES: int = 2_000_000  # 2 MB

    # Proxy Support - Phase 3
    PROXY_URL: Optional[str] = None  # e.g., "http://localhost:8080"

    # Scan Limits
    MAX_ENDPOINTS_PER_SCAN: int = 500
    MAX_DEPTH: int = 5
    SCAN_TIMEOUT: int = 3600  # 1 hour max scan time

    # Random delays for request pacing
    RANDOM_DELAY_MIN: float = 0.1
    RANDOM_DELAY_MAX: float = 0.5

    # Host Intelligence - Phase: DNS/WHOIS/Geolocation
    DNS_TIMEOUT: float = 5.0
    WHOIS_TIMEOUT: float = 8.0
    GEOIP_TIMEOUT: float = 6.0

    # Port Scan - Phase: TCP connect scan
    PORT_SCAN_TIMEOUT: float = 3.0
    PORT_SCAN_CONCURRENCY: int = 10

    # CVE Lookup - Phase: NVD correlation
    CVE_LOOKUP_TIMEOUT: float = 10.0
    CVE_LOOKUP_MAX_CANDIDATES: int = 8  # bounds worst-case time given NVD's public rate limit
    CVE_LOOKUP_SPACING: float = 7.0  # seconds between NVD calls -- stays under 5-req/30s public limit
    # Optional NVD API key. Raises the public limit from 5 to 50 requests per
    # 30 seconds and lets the CPE phase finish much faster.
    NVD_API_KEY: Optional[str] = None
    NVD_API_KEY_SPACING: float = 0.7
    # Cap pagination for a single product so one popular package (nginx has
    # hundreds of CVEs) cannot make a scan run for hours.
    CVE_CPE_MAX_RESULTS: int = 2000
    CVE_MAX_MATCHES_PER_PRODUCT: int = 25

    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the current application settings."""
    return settings
