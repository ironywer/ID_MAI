import uuid

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.crypto.RSA import rsa_keygen, rsa_encrypt
from app.utils.generators import make_pdf

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
    result = {}
    try:
        if method == "rsa":
            keys = rsa_keygen(bits=4096)

            pub = {"n": keys["n"], "e": keys["e"]}

            ct = rsa_encrypt(pub, text.encode("utf-8"))

            encrypted_hex = ct.hex()
            filename = f"{uuid.uuid4()}.pdf"
            filepath = f"static/results/{filename}"
            make_pdf(
                filepath=filepath,
                original=text,
                encrypted=encrypted_hex,
                public_key={"n": hex(pub["n"]), "e": pub["e"]}
            )
            result["pdf_link"] = f"/static/results/{filename}"
            result["encrypted_hex"] = encrypted_hex

            result["public_key"] = {
                "n": hex(keys["n"]),
                "e": keys["e"],
            }

        else:
            result["error"] = "Неизвестный метод"

    except Exception as ex:
        result["error"] = f"{type(ex).__name__}: {ex}"

    return templates.TemplateResponse(
        "encrypt.html",
        {"request": request, "result": result}
    )