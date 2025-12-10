import os

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.routers.auth import router as auth_router
from app.routers.encrypt import router as encrypt_router
from app.routers.main import router as main_router
from app.routers.admin import router as admin_router

app = FastAPI(title="PriceWatch MVP")


ALLOWED_PREFIXES = (
    "/auth/login",
    "/auth/register",
    "/auth/request_code",
    "/auth/verify",
    "/auth/login_yandex",
    "/static",
    "/favicon.ico",
    "/docs",
    "/openapi",
)


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if any(path.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        return await call_next(request)
    if request.session.get("user"):
        return await call_next(request)
    return RedirectResponse(url="/auth/login", status_code=302)


# Make sure SessionMiddleware runs before our guard so request.session is available.
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "change-me"),
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(main_router)
app.include_router(encrypt_router)
app.include_router(auth_router)
app.include_router(admin_router)
