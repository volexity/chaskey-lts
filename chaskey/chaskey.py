"""Pure python Chaskey-LTS cipher implementation."""

import struct


class Chaskey:
    """Pure python Chaskey-LTS cipher implementation."""

    @staticmethod
    def _rol(n: int, rot: int, width: int) -> int:
        return (n << rot % width) & (2**width - 1) | ((n & (2**width - 1)) >> (width - (rot % width)))

    @staticmethod
    def _ror(n: int, rot: int, width: int) -> int:
        return ((n & (2**width - 1)) >> rot % width) | (n << (width - (rot % width)) & (2**width - 1))

    def __init__(self, mode: str, key: bytes, *mode_args: dict) -> None:
        """Initialize the cipher.

        Args:
            self: Cipher object instance
            mode (str): Cipher mode. Must be one of 'ecb', 'cbc', 'ofb' ,'cfb',
                'cfb8', 'ctr', or 'gcm'.
            key (bytes): 16-byte key
            *mode_args (tuple): Parameters unique to mode operation. These are:
                'ecb'
                    None
                'cbc'
                    (0): Initialization vector
                'ofb'
                    (0): Initialization vector
                'cfb'
                    (0): Initialization vector
                'cfb8'
                    (0): Initialization vector
                'ctr'
                    (0): Counter nonce
                'gcm'
                    (0): Counter nonce
                    (1): Validation Tag (ignored by encrypt())

        # Returns:
            None

        Notes: Only CTR mode is currently operational

        """
        self.mode = mode
        self.key = key
        if self.mode.lower() == "ctr":
            # Handle counter mode
            if len(mode_args) < 1:
                msg = "Error: CTR mode requires a nonce"
                raise ValueError(msg)
            if not isinstance(mode_args[0], (bytes, bytearray)):
                raise ValueError("Error: CTR mode nonce must be a " + "bytes-like type")
            self.counter = mode_args[0]
        else:
            msg = "Error: unsupported mode"
            raise ValueError(msg)

    def _chaskey_block(self, enc: bool, buf: bytes) -> bytes:
        if len(self.key) < 16 or len(buf) < 16:  # noqa: PLR2004
            return b""

        v = list(struct.unpack("IIII", buf))
        k = list(struct.unpack("IIII", self.key))

        for x in range(4):
            v[x] ^= k[x]

        for _ in range(16):
            if enc is True:
                v[0] = (v[0] + v[1]) & 0xFFFFFFFF
                v[1] = self._rol(v[1], 5, 32)
                v[1] ^= v[0]
                v[0] = self._rol(v[0], 16, 32)
                v[2] = (v[2] + v[3]) & 0xFFFFFFFF
                v[3] = self._rol(v[3], 8, 32)
                v[3] ^= v[2]
                v[0] = (v[0] + v[3]) & 0xFFFFFFFF
                v[3] = self._rol(v[3], 13, 32)
                v[3] ^= v[0]
                v[2] = (v[2] + v[1]) & 0xFFFFFFFF
                v[1] = self._rol(v[1], 7, 32)
                v[1] ^= v[2]
                v[2] = self._rol(v[2], 16, 32)
            else:
                v[2] = self._ror(v[2], 16, 32)
                v[1] ^= v[2]
                v[1] = self._ror(v[1], 7, 32)
                v[2] = (v[2] - v[1]) & 0xFFFFFFFF
                v[3] ^= v[0]
                v[3] = self._ror(v[3], 13, 32)
                v[0] = (v[0] - v[3]) & 0xFFFFFFFF
                v[3] ^= v[2]
                v[3] = self._ror(v[3], 8, 32)
                v[2] = (v[2] - v[3]) & 0xFFFFFFFF
                v[0] = self._ror(v[0], 16, 32)
                v[1] ^= v[0]
                v[1] = self._ror(v[1], 5, 32)
                v[0] = (v[0] - v[1]) & 0xFFFFFFFF

        for _ in range(4):
            v[_] ^= k[_]

        return struct.pack("IIII", *v)

    @staticmethod
    def _chaskey_pad(buf: bytes) -> bytes:
        if len(buf) < 16:  # noqa: PLR2004
            buf = buf + b"\x00" * (16 - len(buf))
        return buf

    def _chaskey_ctr(self, data: bytes) -> bytes:
        o = bytearray()
        i = 0
        len_remaining = len(data)

        counter = self.counter  # type: ignore[has-type]
        # Encrypt buffer
        while len_remaining:
            k = self._chaskey_block(True, counter)

            len_block = 16
            if len_remaining < 16:  # noqa: PLR2004
                len_block = len_remaining

            for x in range(len_block):
                o.append(data[i] ^ k[x])
                i += 1

            len_remaining -= len_block

            # update counter
            c = int.from_bytes(counter, "big")
            c += 1
            counter = c.to_bytes(16, "big")

        return o

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the initialized cipher.

        Args:
            self: Cipher object instance
            data (bytes): Data to encrypt

        Returns:
            bytes: Encrypted data buffer

        """
        if self.mode == "ctr":
            if not hasattr(self, "counter"):
                raise AttributeError("Error: Must have a nonce to encrypt " + "in CTR mode")
            return self._chaskey_ctr(data)
        msg = "Error: unsupported mode"
        raise ValueError(msg)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the initialized cipher.

        Arguments:
            self: Cipher object instance
            data (bytes): Data to decrypt

        Returns:
            bytes: Decrypted data buffer

        """
        if self.mode == "ctr":
            if not hasattr(self, "counter"):
                raise AttributeError("Error: Must have a nonce to encrypt " + "in CTR mode")
            return self._chaskey_ctr(data)
        msg = "Error: unsupported mode"
        raise ValueError(msg)
