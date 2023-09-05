"""Pure python Chaskey-LTS cipher implementation."""

import struct


class Chaskey():
    """Pure python Chaskey-LTS cipher implementation."""

    @staticmethod
    def _rol(n, rot, width):
        return (
            (n << rot % width) & (2**width-1) |
            ((n & (2**width-1)) >> (width-(rot % width)))
        )

    @staticmethod
    def _ror(n, rot, width):
        return (
            ((n & (2**width-1)) >> rot % width) |
            (n << (width - (rot % width)) & (2**width-1))
        )

    def __init__(self,
                 mode: str,
                 key: bytes,
                 *mode_args) -> None:
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
        Returns:
            None

        Notes: Only CTR mode is currently operational
        """
        self.mode = mode
        self.key = key
        if self.mode.lower() == 'ctr':
            # Handle counter mode
            if len(mode_args) < 1:
                raise ValueError('Error: CTR mode requires a nonce')
            if (
                (type(mode_args[0]) != bytes) and
                (type(mode_args[0]) != bytearray)
            ):
                raise ValueError('Error: CTR mode nonce must be a ' +
                                 'bytes-like type')
            self.counter = mode_args[0]
        else:
            raise ValueError("Error: unsupported mode")

    def _chaskey_block(self, enc: bool, buf: bytes) -> bytes:
        if len(self.key) < 16 or len(buf) < 16:
            return 0

        v = list(struct.unpack('IIII', buf))
        k = list(struct.unpack('IIII', self.key))

        for x in range(0, 4):
            v[x] ^= k[x]

        for x in range(0, 16):
            if enc is True:
                v[0] = (v[0] + v[1]) & 0xffffffff
                v[1] = self._rol(v[1], 5, 32)
                v[1] ^= v[0]
                v[0] = self._rol(v[0], 16, 32)
                v[2] = (v[2] + v[3]) & 0xffffffff
                v[3] = self._rol(v[3], 8, 32)
                v[3] ^= v[2]
                v[0] = (v[0] + v[3]) & 0xffffffff
                v[3] = self._rol(v[3], 13, 32)
                v[3] ^= v[0]
                v[2] = (v[2] + v[1]) & 0xffffffff
                v[1] = self._rol(v[1], 7, 32)
                v[1] ^= v[2]
                v[2] = self._rol(v[2], 16, 32)
            else:
                v[2] = self._ror(v[2], 16, 32)
                v[1] ^= v[2]
                v[1] = self._ror(v[1], 7, 32)
                v[2] = (v[2] - v[1]) & 0xffffffff
                v[3] ^= v[0]
                v[3] = self._ror(v[3], 13, 32)
                v[0] = (v[0] - v[3]) & 0xffffffff
                v[3] ^= v[2]
                v[3] = self._ror(v[3], 8, 32)
                v[2] = (v[2] - v[3]) & 0xffffffff
                v[0] = self._ror(v[0], 16, 32)
                v[1] ^= v[0]
                v[1] = self._ror(v[1], 5, 32)
                v[0] = (v[0] - v[1]) & 0xffffffff

        for x in range(0, 4):
            v[x] ^= k[x]

        return struct.pack('IIII', *v)

    def _chaskey_pad(buf: bytes) -> bytes:
        # Pad buffer to the block length
        if len(buf) < 16:
            b = bytearray(buf)
            for x in range(0, 16-len(buf)):
                b.append(0)
            buf = b
        return buf

    def _chaskey_ctr(self, data: bytes) -> bytes:
        o = bytearray()
        i = 0
        lenRemaining = len(data)

        # Encrypt buffer
        while lenRemaining:
            k = self._chaskey_block(True, self.counter)

            lenBlock = 16
            if lenRemaining < 16:
                lenBlock = lenRemaining

            for x in range(0, lenBlock):
                o.append(data[i] ^ k[x])
                i += 1

            lenRemaining -= lenBlock

            # update counter
            c = int.from_bytes(self.counter, 'big')
            c += 1
            self.counter = c.to_bytes(16, 'big')

        return o

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using the initialized cipher.

        Arguments:
            self: Cipher object instance
            data (bytes): Data to encrypt

        Returns:
            bytes: Encrypted data buffer
        """
        if self.mode == 'ctr':
            if not hasattr(self, 'counter'):
                raise AttributeError('Error: Must have a nonce to encrypt ' +
                                     'in CTR mode')
            return self._chaskey_ctr(data)
        else:
            raise ValueError("Error: unsupported mode")

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the initialized cipher.

        Arguments:
            self: Cipher object instance
            data (bytes): Data to decrypt

        Returns:
            bytes: Decrypted data buffer
        """
        if self.mode == 'ctr':
            if not hasattr(self, 'counter'):
                raise AttributeError('Error: Must have a nonce to encrypt ' +
                                     'in CTR mode')
            return self._chaskey_ctr(data)
        else:
            raise ValueError("Error: unsupported mode")
