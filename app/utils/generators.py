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