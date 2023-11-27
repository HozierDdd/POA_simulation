from aes_cbc import AES_CBC
import base64

global_cipher = AES_CBC()


def xor(bytearray1, bytearray2):
    return bytearray(a ^ b for a, b in zip(bytearray1, bytearray2))


def split_blocks(data):
    length = len(data)
    blocks = [data[i * 16:(i + 1) * 16] for i in range(length // 16)]
    return blocks

def find_bytes(blocks):

    # c_prime = bytearray([b for b in blocks[0]])
    plaintext_byte = bytearray([0 for _ in range(16)])

    for i in range(16):
        expected_padding = bytearray([0 for _ in range(16 - i)] + [(i + 1) for _ in range(i)])
        c_prime = xor(xor(expected_padding, plaintext_byte), blocks[0])
        for byte in list(range(blocks[0][15 - i] + 1, 256)) + list(range(0, blocks[0][15 - i] + 1)):
            c_prime[15 - i] = byte
            # c_prime[15] = (plaintext_byte ^ blocks[0][15] ^ 0x02)

            to_test = base64.b64encode(bytes(c_prime + blocks[1]))
            try:
                global_cipher.decrypt(to_test)
                plaintext_byte[15 - i] = (byte ^ (i + 1) ^ blocks[0][15 - i])
                break
            except Exception as e:
                pass
    return ''.join([chr(b) for b in plaintext_byte if b > 16])

def find_plaintext(ciphertext):
    ciphertext = bytearray(base64.b64decode(ciphertext))
    blocks = split_blocks(ciphertext)
    plaintext = ""
    for i in range(len(blocks)-1):
        plaintext += find_bytes(blocks[i: i+2])

    print(plaintext)

if __name__ == "__main__":
    plaintext = "This is a test of padding oracle attack"
    ciphertext = global_cipher.encrypt(plaintext)
    # find_bytes(ciphertext)
    find_plaintext(ciphertext)
