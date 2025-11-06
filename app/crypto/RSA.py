import math
import gmpy2

from app.utils.generators import gen_big_simple


def modinv(a, m):
    return int(gmpy2.invert(a, m))


def rsa_keygen(bits=65536, e=65537, rounds=64):
    half = bits // 2
    while True:
        p = int(gen_big_simple(half, rounds))
        if math.gcd(e, p - 1) == 1:
            break
    while True:
        q = int(gen_big_simple(half, rounds))
        if q != p and math.gcd(e, q - 1) == 1:
            break


    n = p * q

    lam = gmpy2.lcm(p - 1, q - 1) # Находим наименьшее общее кратное, вместо взаимно простых чисел
    d = modinv(e, lam)

    # Для ускорения расшифровки вычислим CRT параметры
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)

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
    m1 = pow(c % p, dp, p)
    m2 = pow(c % q, dq, q)
    h  = (qinv * (m1 - m2)) % p
    m  = m2 + h * q
    return m

def rsa_encrypt(pub, message: bytes) -> bytes:
    m_int = int.from_bytes(message, "big")
    c_int = rsa_encrypt_int(m_int, pub)
    k = (pub["n"].bit_length() + 7) // 8 # перевод в байты
    return c_int.to_bytes(k, "big")

def rsa_decrypt(priv, ciphertext: bytes) -> bytes:
    c_int = int.from_bytes(ciphertext, "big")
    m_int = rsa_decrypt_int(c_int, priv)
    k = (priv["n"].bit_length() + 7) // 8
    return m_int.to_bytes(k, "big").lstrip(b"\x00")

