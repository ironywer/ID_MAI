import secrets

import gmpy2


def gen_big(rs, bits):
    big = gmpy2.mpz_urandomb(rs, bits)  # генерация большое числа
    big = gmpy2.bit_set(big, bits - 1)  # фикс ведущих нулей
    big |= 1  # теперь точно нечетное
    return big


def gen_big_simple(bits: int, rounds: int) -> int:
    seed = int.from_bytes(  # Конвертирует байты в число
        secrets.token_bytes(32),  # Берет 32 случайных непредсказуемых байта данных
        byteorder='big'
    )
    rs = gmpy2.random_state(seed)  # Инициализация генератора
    while True:
        big = gen_big(rs, bits)
        big_simple = gmpy2.next_prime(big) # Ускоряет поиск
        if (big_simple.bit_length() == bits and
                gmpy2.is_prime(big_simple, rounds) > 0):
            return big

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import os

def make_pdf(filepath: str, original: str, encrypted: str, public_key: dict):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title = styles["Title"]
    subtitle = styles["Heading2"]

    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elems = []

    # Заголовок
    elems.append(Paragraph("RSA Encryption Result", title))
    elems.append(Spacer(1, 20))

    # Исходный текст
    elems.append(Paragraph("Original text:", subtitle))
    elems.append(Paragraph(original.replace("\n", "<br/>"), normal))
    elems.append(Spacer(1, 20))

    # Шифр-текст
    elems.append(Paragraph("Encrypted text (hex):", subtitle))
    elems.append(Paragraph(encrypted.replace("\n", "<br/>"), normal))
    elems.append(Spacer(1, 20))

    # Публичный ключ
    elems.append(Paragraph("Public key:", subtitle))
    elems.append(Paragraph(f"n = {public_key['n']}", normal))
    elems.append(Paragraph(f"e = {public_key['e']}", normal))

    doc.build(elems)