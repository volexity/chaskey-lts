from chaskey import Chaskey


def test_encrypt() -> None:
    key = b"0123456789012345"
    iv = b"0000000000000000"
    chas = Chaskey("ctr", key, iv)
    ciphertext = chas.encrypt(b"foo")
    assert ciphertext == b"\x2b\xda\xd6"


def test_decrypt() -> None:
    key = b"0123456789012345"
    iv = b"0000000000000000"
    chas = Chaskey("ctr", key, iv)
    ciphertext = chas.decrypt(b"\x2b\xda\xd6")
    assert ciphertext == b"foo"
