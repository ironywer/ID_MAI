from typing import List

PI: List[int] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
    218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
    153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
    24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
    160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52,
    44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
    58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18,
    191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
    41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
    178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
    84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
    62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
    40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
    0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165,
    125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
    29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
    27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
    202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9,
    91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,
    75, 99, 182
]

PI_INV: List[int] = [
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158,
    57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96,
    7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224,
    39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229,
    66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25,
    201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175,
    43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212,
    15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127,
    193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166,
    254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120,
    5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106,
    137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210,
    49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46,
    54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22,
    102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227,
    186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250,
    150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23,
    27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13,
    122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235,
    248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19,
    152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244,
    206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26,
    72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0,
    76, 215, 116
]

L_VEC: List[int] = [
    148, 32, 133, 16, 194, 192, 1, 251,
    1, 192, 194, 16, 133, 32, 148, 1
]

# Редукция по полиному x^8 + x^7 + x^6 + x + 1 (0x1C3)
RED_POLY = 0xC3

# побитовое сложение по модулю 2.
def xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Замена байтов по таблице
def S(state: bytes) -> bytes:
    return bytes(PI[b] for b in state)

def S_inv(state: bytes) -> bytes:
    return bytes(PI_INV[b] for b in state)

# Умножение двух байтов как «столбиком», только в двоичной арифметике без переносов,
# с модульным «обрезанием» по полиному
def gf_mul(a: int, b: int) -> int:
    res = 0
    x = a
    y = b
    for _ in range(8):
        if y & 1:
            res ^= x       # если младший бит b = 1, то добавляем x
        y >>= 1            # сдвигаем b
        carry = x & 0x80   # был ли старший бит?
        x = (x << 1) & 0xFF  # умножаем x на 2
        if carry:
            x ^= RED_POLY     # корректируем переполнение
    return res

def R(state: bytes) -> bytes:
    assert len(state) == 16
    s = list(state)
    lbyte = 0
    for i in range(16):
        lbyte ^= gf_mul(s[i], L_VEC[i])
    return bytes([lbyte] + s[:15])

def L(state: bytes) -> bytes:
    y = state
    for _ in range(16):
        y = R(y)
    return y

def R_inv(state: bytes) -> bytes:
    assert len(state) == 16
    s = list(state)
    lsum = 0
    for i in range(15):
        lsum ^= gf_mul(s[i+1], L_VEC[i])
    x15 = lsum ^ s[0]
    return bytes(s[1:] + [x15])

def L_inv(state: bytes) -> bytes:
    y = state
    for _ in range(16):
        y = R_inv(y)
    return y

#rk - раундовые ключи
def X(state: bytes, rk: bytes) -> bytes:
    return xor16(state, rk)

def encrypt_block(block: bytes, rk: list[bytes]) -> bytes:
    assert len(block) == 16 and len(rk) == 10
    state = X(block, rk[0])
    for i in range(1, 10):
        state = X(L(S(state)), rk[i])
    return state

def decrypt_block(block: bytes, rk: list[bytes]) -> bytes:
    assert len(block) == 16 and len(rk) == 10
    state = block
    for i in range(9, 0, -1):
        state = S_inv(L_inv(X(state, rk[i])))
    state = X(state, rk[0])
    return state

def C_i(i: int) -> bytes:
    return L(i.to_bytes(16, 'big'))

def F(k1: bytes, k2: bytes, c: bytes) -> tuple[bytes, bytes]:
    t = L(S(xor16(k1, c)))
    return xor16(t, k2), k1

def expand_keys(master: bytes) -> list[bytes]:
    assert len(master) == 32
    k1, k2 = master[:16], master[16:]
    round_keys = [k1, k2]  # K0, K1
    for j in range(4):     # 4 группы по 8 итераций = 32 итерации
        for i in range(1, 9):
            k1, k2 = F(k1, k2, C_i(8*j + i))
        round_keys.extend([k1, k2])
    return round_keys[:10]

def inc_ctr(c: bytearray):
    for i in range(15, -1, -1):
        c[i] = (c[i] + 1) & 0xFF
        if c[i] != 0:
            break

def kuz_ctr_encrypt(key256: bytes, iv16: bytes, data: bytes) -> bytes:
    rk = expand_keys(key256)
    ctr = bytearray(iv16)
    out = bytearray(len(data))
    off = 0
    while off < len(data):
        keystream = encrypt_block(bytes(ctr), rk)
        n = min(16, len(data) - off)
        for i in range(n):
            out[off+i] = data[off+i] ^ keystream[i]
        off += n
        inc_ctr(ctr)
    return bytes(out)

kuz_ctr_decrypt = kuz_ctr_encrypt