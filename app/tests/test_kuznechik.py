from app.crypto.kuz import expand_keys, encrypt_block, decrypt_block


def test_kuznechik_block():
    """
    Тест из стандарта ГОСТ Р 34.12-2015 (RFC 7801).
    Проверяет, что encrypt_block и decrypt_block работают корректно.
    """

    key = bytes.fromhex(
        "8899aabbccddeeff0011223344556677"
        "fedcba98765432100123456789abcdef"
    )

    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")

    expected_ciphertext = bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd")

    # генерируем раундовые ключи
    rk = expand_keys(key)

    # шифрование
    ct = encrypt_block(plaintext, rk)
    assert ct == expected_ciphertext, "encrypt_block даёт неправильный результат"

    # расшифрование
    pt = decrypt_block(ct, rk)
    assert pt == plaintext, "decrypt_block не возвращает исходный блок"
