import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.config import settings, BASE_DIR
from app.database import init_db
from app.services.device_inventory import device_inventory
from app.services.router_adapter import router_service
from app.services.discovery import discovery_service, get_nmap_path
from app.services.monitoring import monitoring_service

from app.api.devices import router as devices_router
from app.api.scan import router as scan_router
from app.api.router import router as router_ctrl
from app.api.settings import router as settings_router
from app.api.analytics import router as analytics_router
from app.api.auth import router as auth_router, get_current_user_optional, has_any_admin, CSRF_COOKIE_NAME, get_csrf_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("netsentinel.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and start monitoring
    logger.info("Starting Net Sentinel by Software Vantage...")
    init_db()

    # Start background monitoring service (which runs periodic scans in background)
    monitoring_service.start_background_monitoring()
    yield
    # Shutdown
    monitoring_service.stop_background_monitoring()
    logger.info("Net Sentinel shut down cleanly.")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Free, self-hosted home network monitoring and device management application.",
    lifespan=lifespan
)

# Static and Templates
STATIC_DIR = BASE_DIR / "app" / "static"
TEMPLATES_DIR = BASE_DIR / "app" / "templates"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Include API Routers
app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(scan_router)
app.include_router(router_ctrl)
app.include_router(settings_router)
app.include_router(analytics_router)

@app.middleware("http")
async def ensure_csrf_cookie(request: Request, call_next):
    response = await call_next(request)
    if CSRF_COOKIE_NAME not in request.cookies:
        token = get_csrf_token(request)
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=False,
            samesite="lax",
            max_age=7 * 24 * 3600
        )
    return response

@app.get("/api/summary")
def get_dashboard_summary():
    """Returns the 8 summary metrics specified for the dashboard overview."""
    net_info = discovery_service.get_network_info()
    r_status = router_service.get_status()
    summary = device_inventory.get_summary_metrics(router_status_str=r_status["connection_status"])
    summary["router_model"] = settings.ROUTER_MODEL
    summary["router_gateway"] = settings.ROUTER_GATEWAY
    summary["nmap_installed"] = net_info["nmap_installed"]
    summary["current_subnet"] = net_info["subnet"]
    summary["host_ip"] = net_info["host_ip"]
    return summary

@app.get("/", response_class=HTMLResponse)
def index_page(request: Request):
    """Render main Net Sentinel single-page responsive dashboard."""
    user = get_current_user_optional(request)
    admin_exists = has_any_admin()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "developer": settings.DEVELOPER,
            "tagline": settings.APP_TAGLINE,
            "current_user": user,
            "admin_exists": admin_exists
        }
    )
