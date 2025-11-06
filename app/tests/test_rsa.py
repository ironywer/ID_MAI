def test_rsa_encrypt_decrypt():
    """
    Проверяет, что RSA корректно шифрует и расшифровывает данные.
    Использует keygen -> encrypt -> decrypt.
    """

    from app.crypto.RSA import rsa_keygen, rsa_encrypt, rsa_decrypt

    keys = rsa_keygen(bits=1024)  # маленький ключ, чтобы тесты были быстрыми
    pub = {"n": keys["n"], "e": keys["e"]}

    message = b"hello world!"
    ciphertext = rsa_encrypt(pub, message)
    plaintext = rsa_decrypt(keys, ciphertext)

    assert plaintext == message, "RSA decrypt() не возвращает исходный текст"