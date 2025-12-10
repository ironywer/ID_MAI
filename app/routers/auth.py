import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette import status

from app.utils.auth import store, hash_password
from app.utils.emailer import send_email


router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="app/templates")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_action(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
):
    identifier = login.strip()
    if not identifier or not password:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Login and password are required."},
        )

    entry = store.get_user(identifier) or store.get_user_by_email(identifier)
    if not entry:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})

    username = entry.get("username", identifier)
    if entry.get("password") != hash_password(password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})

    # Password path: log in directly
    request.session["user"] = username
    request.session["role"] = entry.get("role", "user")
    # Clear any pending
    request.session.pop("pending_user", None)
    request.session.pop("pending_role", None)
    request.session.pop("pending_code", None)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.post("/request_code", response_class=HTMLResponse)
async def request_code(
    request: Request,
    login: str = Form(...),
):
    identifier = login.strip()
    if not identifier:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Provide username or email to receive a code."},
        )
    entry = store.get_user(identifier) or store.get_user_by_email(identifier)
    if not entry:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "User not found."},
        )

    username = entry.get("username", identifier)
    code = os.urandom(3).hex()  # 6 hex chars
    send_email(
        to=entry.get("email") or "unknown@example.com",
        subject="Your login code",
        body=f"Your one-time login code: {code}",
    )

    request.session["pending_user"] = username
    request.session["pending_role"] = entry.get("role", "user")
    request.session["pending_code"] = code
    request.session["pending_email"] = entry.get("email") or "unknown@example.com"
    return RedirectResponse(url="/auth/verify", status_code=status.HTTP_302_FOUND)


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "error": None},
    )


@router.post("/register", response_class=HTMLResponse)
async def register_action(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    username = username.strip()
    email = email.strip()
    if not username or not password or not email:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username, email and password are required."},
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Passwords do not match."},
        )

    role = "admin" if username == ADMIN_USERNAME else "user"
    created = store.create_user(username, password, role=role, email=email)
    if not created:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "User already exists."},
        )

    request.session["user"] = username
    request.session["role"] = role
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    if not request.session.get("pending_user"):
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        "verify.html",
        {"request": request, "error": None},
    )


@router.post("/verify", response_class=HTMLResponse)
async def verify_action(request: Request, code: str = Form(...)):
    pending_user = request.session.get("pending_user")
    pending_role = request.session.get("pending_role")
    pending_code = request.session.get("pending_code")

    if not pending_user or not pending_code:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    if code.strip() != pending_code:
        return templates.TemplateResponse(
            "verify.html",
            {"request": request, "error": "Invalid code."},
        )

    # Success: promote pending to active session
    request.session["user"] = pending_user
    request.session["role"] = pending_role or "user"
    request.session.pop("pending_user", None)
    request.session.pop("pending_role", None)
    request.session.pop("pending_code", None)
    request.session.pop("pending_email", None)

    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
