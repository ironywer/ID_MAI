from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.utils.auth import store


router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="app/templates")


def _require_admin(request: Request) -> bool:
    return request.session.get("role") == "admin"


@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if not _require_admin(request):
        return RedirectResponse("/", status_code=302)
    users = store.list_users()
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "users": users},
    )


@router.post("/delete", response_class=HTMLResponse)
async def delete_user(request: Request, username: str = Form(...)):
    if not _require_admin(request):
        return RedirectResponse("/", status_code=302)
    # Prevent deleting yourself to avoid locking out admin accidentally.
    if username != request.session.get("user"):
        store.delete_user(username)
    return RedirectResponse("/admin/", status_code=302)
