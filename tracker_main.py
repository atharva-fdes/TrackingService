"""
Standalone Email Tracking Server
Deploy this on Render.com / Railway (NOT Azure)
It receives pixel/click hits and forwards real events to your Azure backend.
"""

import logging
import ipaddress
import time
import httpx

from fastapi import FastAPI, Request
from fastapi.responses import Response, RedirectResponse
import os

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Your Azure backend URL ─────────────────────────────────────
AZURE_BACKEND_URL = os.getenv("AZURE_BACKEND_URL", "https://obmarketing.azurewebsites.net")
INTERNAL_SECRET   = os.getenv("INTERNAL_SECRET", "change-me-secret")  # shared secret

# ── Fast-open protection ───────────────────────────────────────
FAST_OPEN_THRESHOLD_SECONDS = 10

# 1x1 transparent GIF
_PIXEL_GIF = (
    b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
    b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00"
    b"\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
    b"\x44\x01\x00\x3b"
)

# ── Gmail image proxy UAs (separate for distinct logging) ──────
GMAIL_PROXY_AGENTS = [
    "googleimageproxy",
]

# ── Bot / scanner user-agent keywords ──────────────────────────
BOT_AGENTS = [
    "outlook", "microsoft", "exchange", "safelinks",
    "proofpoint", "barracuda", "mimecast", "symantec",
    "spider", "crawler", "bot",
    "bingbot", "msnbot", "office", "curl", "scanner",
    "wget", "monitor", "urlscan", "linkchecker",
    "preview", "prefetch", "validator",
]

# ── Known bot/scanner IP ranges ────────────────────────────────
_BOT_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("20.0.0.0/8"),      # Azure public
    ipaddress.ip_network("40.64.0.0/10"),    # Azure public
    ipaddress.ip_network("52.0.0.0/8"),      # Azure public
]


def get_real_ip(request: Request) -> str:
    for header in ["x-client-ip", "x-forwarded-for", "cf-connecting-ip", "x-real-ip"]:
        val = request.headers.get(header, "")
        if val:
            ip = val.split(",")[0].strip()
            # strip port
            if ":" in ip and ip.count(":") == 1:
                ip = ip.split(":")[0]
            if ip:
                return ip
    return request.client.host


def classify_request(request: Request) -> str | None:
    """
    Classify request as bot/proxy or real.

    Returns a block-reason string if the request should be blocked,
    or None if the request is legitimate.
    """
    ua = request.headers.get("user-agent", "").lower()
    ip = get_real_ip(request)

    # 1. Gmail image proxy – separate category
    if any(g in ua for g in GMAIL_PROXY_AGENTS):
        logger.info("GMAIL_PROXY_BLOCKED | ip=%s | ua=%s", ip, ua)
        return "GMAIL_PROXY_BLOCKED"

    # 2. Bot / scanner user-agent check
    if any(b in ua for b in BOT_AGENTS):
        logger.info("BOT_UA_BLOCKED | ip=%s | ua=%s", ip, ua)
        return "BOT_UA_BLOCKED"

    # 3. Empty user-agent = bot/scanner
    if not ua:
        logger.info("BOT_UA_BLOCKED | ip=%s | ua=(empty)", ip)
        return "BOT_UA_BLOCKED"

    # 4. Internal / reserved IP range check
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in _BOT_NETWORKS):
            logger.info("BOT_IP_BLOCKED | ip=%s", ip)
            return "BOT_IP_BLOCKED"
    except ValueError:
        pass

    return None


async def notify_azure(endpoint: str, payload: dict):
    """Forward confirmed real event to Azure backend."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{AZURE_BACKEND_URL}{endpoint}",
                json=payload,
                headers={"X-Internal-Secret": INTERNAL_SECRET}
            )
    except Exception as e:
        logger.error("Failed to notify Azure: %s", e)


@app.get("/track/open/{tracking_id}", response_class=Response)
async def track_open(tracking_id: str, request: Request):
    real_ip = get_real_ip(request)
    ua = request.headers.get("user-agent", "")

    if request.method == "HEAD":
        return Response(status_code=200)

    # ── Filter 1-3: bot / proxy / IP ───────────────────────────
    block_reason = classify_request(request)
    if block_reason:
        logger.info("%s | tracking_id=%s | ip=%s", block_reason, tracking_id, real_ip)
        return Response(content=_PIXEL_GIF, media_type="image/gif")

    # ── All filters passed — real event ────────────────────────
    logger.info("OPEN_REAL | tracking_id=%s | ip=%s | ua=%s", tracking_id, real_ip, ua)

    # Forward to Azure backend with fast-open threshold
    await notify_azure("/api/v1/internal/record-open", {
        "tracking_id": tracking_id,
        "client_ip": real_ip,
        "user_agent": ua,
        "min_elapsed_seconds": FAST_OPEN_THRESHOLD_SECONDS,
    })

    return Response(content=_PIXEL_GIF, media_type="image/gif")


@app.get("/track/click/{tracking_id}")
async def track_click(tracking_id: str, request: Request, url: str = "https://eotcranedesigner.com/"):
    real_ip = get_real_ip(request)
    ua = request.headers.get("user-agent", "")

    if request.method == "HEAD":
        return Response(status_code=200)

    # ── Filter 1-3: bot / proxy / IP ───────────────────────────
    block_reason = classify_request(request)
    if block_reason:
        logger.info("%s | tracking_id=%s | ip=%s", block_reason, tracking_id, real_ip)
        return RedirectResponse(url=url, status_code=307)

    # ── All filters passed — real event ────────────────────────
    logger.info("CLICK_REAL | tracking_id=%s | ip=%s | ua=%s", tracking_id, real_ip, ua)

    await notify_azure("/api/v1/internal/record-click", {
        "tracking_id": tracking_id,
        "url": url,
        "client_ip": real_ip,
        "user_agent": ua,
    })

    return RedirectResponse(url=url, status_code=307)


@app.get("/health")
def health():
    return {"status": "ok"}
