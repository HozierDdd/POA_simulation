import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

class AES_CBC(object):
    def __init__(self, key=get_random_bytes(32)):
        self.key = key

    def _split_blocks(self, data):
        length = len(data)
        blocks = [data[i * 16:(i + 1) * 16] for i in range(len(data) // 16)]
        return blocks

    def _add_padding(self, data):
        padding = 16 - (len(data) % 16)
        return data + bytearray([padding] * padding)

    def _check_and_strip_padding(self, data):
        expected_padding = data[-1]
        if data[-expected_padding:] == bytearray([expected_padding]) * expected_padding:
            return data[:-expected_padding]
        raise ValueError("Invalid padding")

    def encrypt(self, plaintext):
        plaintext = self._add_padding(bytearray(plaintext, encoding='utf-8'))
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext_blocks = [cipher.encrypt(block) for block in self._split_blocks(plaintext)]
        return base64.b64encode(iv + b''.join(ciphertext_blocks))

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext_blocks = [cipher.decrypt(block) for block in self._split_blocks(ciphertext)]
        return self._check_and_strip_padding(b''.join(plaintext_blocks)).decode('utf-8')

