from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

from app.crypto.constants.streebog_tables import DIRECT_SBOX, LINEAR_LOOKUP


MASK64 = 0xFFFFFFFFFFFFFFFF
BLOCK_SIZE = 64

ROUND_CONSTANTS = [
    [0x0745A6F2596580DD, 0x234D74CC36747605, 0x15D360A4082A42A2, 0x0169679291E07C4B, 0xFCC485758DB84E71, 0x16D0452E43766A2F, 0x1F7C65C0812FCBEB, 0xE9DACA1EDA5B08B1],
    [0xB79BB121700479E6, 0x56CDCBD71BA2DD55, 0xCAA70ADBC261B55C, 0x5899D6126B17B59A, 0x3101B5160F5ED561, 0x982B230A72EAFEF3, 0xD7B5700F469DE34F, 0x1A2F9DA98AB5A36F],
    [0xB20ABA0AF5961E99, 0x31DB7A8643F4B6C2, 0x09DB6260373AC9C1, 0xB19E3590E40FE2D3, 0x7B7B29B11475EAF2, 0x8B1F9C525F5EF106, 0x35843D6A28FC390A, 0xC72FCE2BACDC74F5],
    [0x2ED1E384BCBE0C22, 0xF137E893A1EA5334, 0xBE0352933313B7D8, 0x75D603ED822CD7A9, 0x3F355E68AD1C729D, 0x7D3C5C337E858E48, 0xDDE4715DA0E148F9, 0xD26615E8B3DF1FEF],
    [0x57FE6C7CFD581760, 0xF563EAA97EA2567A, 0x161A2723B700FFDF, 0xA3F53A254717CDBF, 0xBDFF0F80D7359E35, 0x4A1086161F1C157F, 0x6323A96C0C413F9A, 0x994747ADAC6BEA4B],
    [0x6E7D64467A4068FA, 0x354F903672C571BF, 0xB6C6BEC2661FF20A, 0xB4B79A1CB7A6FACF, 0xC68EF09AB49A7F18, 0x6CA44251F9C4662D, 0xC039307A3BC3A46F, 0xD9D33A1DAEAE4FAE],
    [0x93D4143A4D568688, 0xF34A3CA24C451735, 0x04054A2883694706, 0x372C822DC5AB9209, 0xC9937A19333E47D3, 0xC987BFE6C7C69E39, 0x540924BFFE86AC51, 0xECC5AAEE160EC7F4],
    [0x1EE702BFD40D7FA4, 0xD9A8515935C2AC36, 0x2FC4A5D12B8DD169, 0x90069B92CB2B89F4, 0x9AC4DB4D3B44B489, 0x1EDE369C71F8B74E, 0x41416E0C02AAE703, 0xA7C9934D425B1F9B],
    [0xDB5A238351446172, 0x602A1FCB92DC380E, 0x549C07A69A8A2B7B, 0xB1CEB2DB0B440A80, 0x84090DE0B755D93C, 0x244289251B3A7D3A, 0xDE5F16ECD89A4C94, 0x9B223116545A8F37],
    [0xED9C4598FBC7B474, 0xC3B63B15D1FA9836, 0xF452763B306C1E7A, 0x4B3369AF0267E79F, 0x0361331B8AE1FF1F, 0xDB788AFF1CE74189, 0xF3F3E4B248E52A38, 0x526F0580A6DEBEAB],
    [0x1B2DF381CDA4CA6B, 0x5DD86FC04A59A2DE, 0x986E477D1DCDBAEF, 0xCAB948EAEF711D8A, 0x7966841421800120, 0x6107ABEBBB6BFAD8, 0x94FE5A63CDC60230, 0xFB89C8EFD09ECD7B],
    [0x20D71BF14A92BC48, 0x991BB2D9D517F4FA, 0x5228E188AAA41DE7, 0x86CC91189DEF805D, 0x9B9F2130D41220F8, 0x771DDFBC323CA4CD, 0x7AB14904B08013D2, 0xBA3116F167E78E37],
]

V512 = [0x0002000000000000, 0, 0, 0, 0, 0, 0, 0]
ZEROES = [0, 0, 0, 0, 0, 0, 0, 0]
IV512 = bytes(BLOCK_SIZE)
IV256 = bytes([1] * BLOCK_SIZE)


def _bytes_to_uints(block: bytes) -> List[int]:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Expected {BLOCK_SIZE} bytes, got {len(block)}")
    return [int.from_bytes(block[i * 8 : (i + 1) * 8], "big") for i in range(8)]


def _uints_to_bytes(words: Iterable[int]) -> bytes:
    vals = list(words)
    if len(vals) != 8:
        raise ValueError(f"Expected 8 uint64 values, got {len(vals)}")
    return b"".join((v & MASK64).to_bytes(8, "big") for v in vals)


def _pad_block(data: bytes) -> bytes:
    if len(data) > BLOCK_SIZE:
        raise ValueError("Cannot pad data longer than one block")
    padded = bytearray(BLOCK_SIZE)
    padded[: len(data)] = data
    if len(data) < BLOCK_SIZE:
        padded[len(data)] = 1
    return bytes(padded)


def _reverse_words(words: Iterable[int]) -> List[int]:
    raw = bytearray(BLOCK_SIZE)
    for i, val in enumerate(words):
        raw[i * 8 : (i + 1) * 8] = (val & MASK64).to_bytes(8, "big")
    raw.reverse()
    return [int.from_bytes(raw[i * 8 : (i + 1) * 8], "big") for i in range(8)]


def _add512(lhs: Iterable[int], rhs: Iterable[int]) -> List[int]:
    a = _reverse_words(lhs)
    b = _reverse_words(rhs)
    res = [0] * 8
    carry = 0
    for idx in range(7, -1, -1):
        total = a[idx] + b[idx] + carry
        res[idx] = total & MASK64
        carry = 1 if total >> 64 else 0
    return _reverse_words(res)


def _xor_in_place(dst: List[int], src: Iterable[int]) -> None:
    for i, v in enumerate(src):
        dst[i] = (dst[i] ^ v) & MASK64


def _s_transform(state: List[int]) -> None:
    for i, val in enumerate(state):
        tmp = val
        for _ in range(8):
            subbed = DIRECT_SBOX[tmp & 0xFF]
            tmp >>= 8
            tmp |= subbed
        state[i] = tmp & MASK64


def _p_transform(state: List[int]) -> None:
    as_bytes = bytearray(BLOCK_SIZE)
    for i, v in enumerate(state):
        as_bytes[i * 8 : (i + 1) * 8] = (v & MASK64).to_bytes(8, "big")
    permuted = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        permuted[i] = as_bytes[(i % 8) * 8 + (i // 8)]
    for i in range(8):
        state[i] = int.from_bytes(permuted[i * 8 : (i + 1) * 8], "big")


def _l_transform(state: List[int]) -> None:
    for i, v in enumerate(state):
        state[i] = (
            LINEAR_LOOKUP[7][(v >> 56) & 0xFF]
            ^ LINEAR_LOOKUP[6][(v >> 48) & 0xFF]
            ^ LINEAR_LOOKUP[5][(v >> 40) & 0xFF]
            ^ LINEAR_LOOKUP[4][(v >> 32) & 0xFF]
            ^ LINEAR_LOOKUP[3][(v >> 24) & 0xFF]
            ^ LINEAR_LOOKUP[2][(v >> 16) & 0xFF]
            ^ LINEAR_LOOKUP[1][(v >> 8) & 0xFF]
            ^ LINEAR_LOOKUP[0][v & 0xFF]
        ) & MASK64


def _xspl(buffer: List[int], constant: Iterable[int]) -> None:
    _xor_in_place(buffer, constant)
    _s_transform(buffer)
    _p_transform(buffer)
    _l_transform(buffer)


def _g(h: List[int], m: List[int], n: List[int]) -> None:
    h_temp = h.copy()
    _xspl(h, n)
    k = h.copy()
    _xspl(h, m)
    for constant in ROUND_CONSTANTS[:-1]:
        _xspl(k, constant)
        _xspl(h, k)
    _xspl(k, ROUND_CONSTANTS[-1])
    _xor_in_place(h, k)
    _xor_in_place(h, h_temp)
    _xor_in_place(h, m)


@dataclass
class Streebog:

    digest_size: int = 64
    h: List[int] = field(init=False)
    n: List[int] = field(init=False)
    sigma: List[int] = field(init=False)
    buffer: bytearray = field(init=False)

    def __post_init__(self) -> None:
        if self.digest_size not in (32, 64):
            raise ValueError("digest_size must be either 32 or 64 bytes")
        self.reset()

    def reset(self) -> None:
        self.h = _bytes_to_uints(IV256 if self.digest_size == 32 else IV512)
        self.n = [0] * 8
        self.sigma = [0] * 8
        self.buffer = bytearray()

    def update(self, data: bytes) -> "Streebog":
        if not data:
            return self
        view = memoryview(data)
        idx = 0
        while idx < len(view):
            to_take = min(BLOCK_SIZE - len(self.buffer), len(view) - idx)
            self.buffer.extend(view[idx : idx + to_take])
            idx += to_take
            if len(self.buffer) == BLOCK_SIZE:
                block_words = _bytes_to_uints(self.buffer)
                self.buffer.clear()
                _g(self.h, block_words, self.n)
                self.n = _add512(self.n, V512)
                self.sigma = _add512(self.sigma, block_words)
        return self

    def _finalize(self) -> bytes:
        padded = _pad_block(self.buffer)
        m = _bytes_to_uints(padded)

        h_out = self.h.copy()
        n_out = self.n.copy()
        sigma_out = self.sigma.copy()

        _g(h_out, m, n_out)

        bit_len = len(self.buffer) * 8
        length_word = int.from_bytes(bit_len.to_bytes(8, "big")[::-1], "big")
        n_out = _add512(n_out, [length_word, 0, 0, 0, 0, 0, 0, 0])
        sigma_out = _add512(sigma_out, m)

        _g(h_out, n_out, ZEROES)
        _g(h_out, sigma_out, ZEROES)

        out = _uints_to_bytes(h_out)
        return out[32:] if self.digest_size == 32 else out

    def digest(self) -> bytes:
        return self._finalize()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "Streebog":
        clone = Streebog(self.digest_size)
        clone.h = self.h.copy()
        clone.n = self.n.copy()
        clone.sigma = self.sigma.copy()
        clone.buffer = bytearray(self.buffer)
        return clone


def new(digest_size: int = 64) -> Streebog:
    return Streebog(digest_size)


__all__ = ["Streebog", "new"]
