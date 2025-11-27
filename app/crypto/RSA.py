import math
import time

import gmpy2
import logging

from app.utils.generators import gen_big_simple

logger = logging.getLogger(__name__)

def modinv(a, m):
    return int(gmpy2.invert(a, m))


def rsa_keygen(bits=65536, e=65537, rounds=64):
    half = bits // 2
    start = time.perf_counter()
    logger.info("RSA keygen started: bits=%d, e=%d, rounds=%d", bits, e, rounds)

    while True:
        p = int(gen_big_simple(half, rounds))
        if math.gcd(e, p - 1) == 1:
            break

    logger.info("Prime p generated: bits=%d", p.bit_length())

    while True:
        q = int(gen_big_simple(half, rounds))
        if q != p and math.gcd(e, q - 1) == 1:
            break

    logger.info("Prime q generated: bits=%d", q.bit_length())

    n = p * q

    logger.info("Modulus n generated: bits=%d", n.bit_length())

    lam = gmpy2.lcm(p - 1, q - 1) # Находим наименьшее общее кратное, вместо взаимно простых чисел
    d = modinv(e, lam)

    # Для ускорения расшифровки вычислим CRT параметры
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)

    elapsed = time.perf_counter() - start
    logger.info("RSA-%d keygen finished in %.2f seconds", bits, elapsed)
    return {
        "n": n, "e": e, "d": d,
        "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv
    }

def rsa_encrypt_int(m: int, pub) -> int:
    n, e = pub["n"], pub["e"]
    if not (0 <= m < n):
        raise ValueError("message representative out of range")
    return pow(m, e, n)

def rsa_decrypt_int(c: int, priv) -> int:
    n, p, q, dp, dq, qinv = priv["n"], priv["p"], priv["q"], priv["dp"], priv["dq"], priv["qinv"]
    if not (0 <= c < n):
        raise ValueError("ciphertext out of range")
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h  = (qinv * (m1 - m2)) % p
    m  = m2 + h * q
    return m

def rsa_encrypt(pub, message: bytes) -> bytes:
    m_int = int.from_bytes(message, "big")
    c_int = rsa_encrypt_int(m_int, pub)
    n_bits = pub["n"].bit_length()
    logger.info("Encrypting message: %d bytes, n_bits=%d", len(message), n_bits)
    k = (n_bits + 7) // 8 # перевод в байты
    ciphertext = c_int.to_bytes(k, "big")
    logger.info("Encryption done: ciphertext size=%d bytes", len(ciphertext))
    return ciphertext


def rsa_decrypt(priv, ciphertext: bytes) -> bytes:
    n_bits = priv["n"].bit_length()
    logger.info("Decrypting ciphertext: %d bytes, n_bits=%d", len(ciphertext), n_bits)
    c_int = int.from_bytes(ciphertext, "big")
    m_int = rsa_decrypt_int(c_int, priv)
    k = (n_bits + 7) // 8
    message = m_int.to_bytes(k, "big").lstrip(b"\x00")

    logger.info("Decryption done: plaintext size=%d bytes", len(message))
    return message

