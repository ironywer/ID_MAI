import binascii as ba
import logging
from app.crypto.streebog import new


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def test_streebog_empty():
    h512 = new(64)
    h512.update(b"")
    assert h512.hexdigest() == (
        "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7"
        "362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"
    )


def test_streebog_quickfox():
    m = b"The quick brown fox jumps over the lazy dog"
    h512 = new(64)
    h512.update(m)
    assert h512.hexdigest() == (
        "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b9"
        "7e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe"
    )


def test_streebog_hello_world():
    m = b"hello world"
    h512 = new(64)
    h512.update(m)
    assert h512.hexdigest() == (
        "84d883ede9fa6ce855d82d8c278ecd9f5fc88bf0602831ae0c38b9b506ea3cb02f3"
        "fa076b8f5664adf1ff862c0157da4cc9a83e141b738ff9268a9ba3ed6f563"
    )
