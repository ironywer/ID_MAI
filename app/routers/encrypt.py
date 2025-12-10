import secrets
import uuid

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.crypto import streebog
from app.crypto.RSA import rsa_keygen, rsa_encrypt
from app.crypto.kuz import kuz_ctr_encrypt
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
    text: str = Form(...),
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
                public_key={"n": hex(pub["n"]), "e": pub["e"]},
                algorithm="RSA",
            )
            result["pdf_link"] = f"/static/results/{filename}"
            result["encrypted_hex"] = encrypted_hex

            result["public_key"] = {
                "n": hex(keys["n"]),
                "e": keys["e"],
            }
            result["method"] = "rsa"

        elif method == "kuznechik":
            key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            ciphertext = kuz_ctr_encrypt(key, iv, text.encode("utf-8"))
            result["kuznechik"] = {
                "cipher_hex": ciphertext.hex(),
                "key_hex": key.hex(),
                "iv_hex": iv.hex(),
            }
            result["method"] = "kuznechik"
            filename = f"{uuid.uuid4()}.pdf"
            filepath = f"static/results/{filename}"
            make_pdf(
                filepath=filepath,
                original=text,
                encrypted=result["kuznechik"]["cipher_hex"],
                public_key=None,
                algorithm="Kuznechik",
                extra={"Key": result["kuznechik"]["key_hex"], "IV": result["kuznechik"]["iv_hex"]},
            )
            result["pdf_link"] = f"/static/results/{filename}"

        elif method == "streebog":
            hasher = streebog.new(64)
            hasher.update(text.encode("utf-8"))
            result["streebog"] = hasher.hexdigest()
            result["method"] = "streebog"
            filename = f"{uuid.uuid4()}.pdf"
            filepath = f"static/results/{filename}"
            make_pdf(
                filepath=filepath,
                original=text,
                encrypted=result["streebog"],
                public_key=None,
                algorithm="Streebog (GOST R 34.11-2012)",
            )
            result["pdf_link"] = f"/static/results/{filename}"

        else:
            result["error"] = "Unknown method"

    except Exception as ex:
        result["error"] = f"{type(ex).__name__}: {ex}"

    return templates.TemplateResponse(
        "encrypt.html",
        {"request": request, "result": result},
    )
