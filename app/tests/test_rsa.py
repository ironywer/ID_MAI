import logging
import time

from app.crypto.RSA import rsa_keygen, rsa_encrypt, rsa_decrypt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

def test_rsa_encrypt_decrypt():
    """
    Проверяет, что RSA корректно шифрует и расшифровывает данные.
    Использует keygen -> encrypt -> decrypt.
    """
    start = time.perf_counter()

    keys = rsa_keygen(bits=32768)  # маленький ключ, чтобы тесты были быстрыми
    n = keys["n"]  # или как у тебя хранится модуль
    pub = {"n": keys["n"], "e": keys["e"]}

    message = b"hello world!"
    ciphertext = rsa_encrypt(pub, message)
    plaintext = rsa_decrypt(keys, ciphertext)

    assert plaintext == message, "RSA decrypt() не возвращает исходный текст"
    total = time.perf_counter() - start
    logging.getLogger(__name__).info("Full cycle (keygen+encrypt+decrypt) took %.2f seconds", total)