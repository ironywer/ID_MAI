from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.crypto.RSA import rsa_keygen, rsa_encrypt

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/encrypt", response_class=HTMLResponse)
async def encrypt_page(request: Request):
    return templates.TemplateResponse("encrypt.html", {"request": request})


@router.post("/encrypt", response_class=HTMLResponse)
def encrypt_action(
    request: Request,
    method: str = Form(...),
    text: str = Form(...)
):
    result_hex = None
    error = None

    try:
        if method == "rsa":
            keys = rsa_keygen(bits=4096)                       # приватный ключ (содержит n,e,d,p,q,dp,dq,qinv)
            pub = {"n": keys["n"], "e": keys["e"]}    # публичная часть
            ct = rsa_encrypt(pub, text.encode("utf-8"))  # bytes
            result_hex = ct.hex()
        else:
            error = "Неизвестный метод"
    except Exception as ex:
        error = f"{type(ex).__name__}: {ex}"

    return templates.TemplateResponse(
        "encrypt.html",
        {"request": request, "result": {"encrypted_hex": result_hex, "error": error}}
    )