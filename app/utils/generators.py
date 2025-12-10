import secrets
import os

import gmpy2
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def gen_big(rs, bits):
    big = gmpy2.mpz_urandomb(rs, bits)  # random mpz of size bits
    big = gmpy2.bit_set(big, bits - 1)  # ensure high bit set
    big |= 1  # ensure odd
    return big


def gen_big_simple(bits: int, rounds: int) -> int:
    seed = int.from_bytes(
        secrets.token_bytes(32),
        byteorder="big",
    )
    rs = gmpy2.random_state(seed)
    while True:
        big = gen_big(rs, bits)
        big_simple = gmpy2.next_prime(big)
        if big_simple.bit_length() == bits and gmpy2.is_prime(big_simple, rounds) > 0:
            return big_simple


def _register_font_for_unicode() -> str | None:
    """Try to register a TTF font that supports Cyrillic/Unicode text."""
    candidates = [
        ("DejaVuSans", r"C:\Windows\Fonts\DejaVuSans.ttf"),
        ("Arial", r"C:\Windows\Fonts\arial.ttf"),
        ("TimesNewRoman", r"C:\Windows\Fonts\times.ttf"),
    ]
    for name, path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                return name
            except Exception:
                continue
    return None


def make_pdf(
    filepath: str,
    original: str,
    encrypted: str,
    public_key: dict | None = None,
    algorithm: str = "RSA",
    extra: dict | None = None,
) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title = styles["Title"]
    subtitle = styles["Heading2"]

    font_name = _register_font_for_unicode()
    if font_name:
        for sty in (normal, title, subtitle):
            sty.fontName = font_name

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elems = []

    elems.append(Paragraph(f"{algorithm} Result", title))
    elems.append(Spacer(1, 20))

    elems.append(Paragraph("Original text:", subtitle))
    elems.append(Paragraph(original.replace("\n", "<br/>"), normal))
    elems.append(Spacer(1, 20))

    elems.append(Paragraph("Output (hex):", subtitle))
    elems.append(Paragraph(encrypted.replace("\n", "<br/>"), normal))
    elems.append(Spacer(1, 20))

    if public_key:
        elems.append(Paragraph("Public key:", subtitle))
        elems.append(Paragraph(f"n = {public_key.get('n')}", normal))
        elems.append(Paragraph(f"e = {public_key.get('e')}", normal))
        elems.append(Spacer(1, 20))

    if extra:
        elems.append(Paragraph("Details:", subtitle))
        for k, v in extra.items():
            elems.append(Paragraph(f"{k}: {v}", normal))
        elems.append(Spacer(1, 20))

    doc.build(elems)
