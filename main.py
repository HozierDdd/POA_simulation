from aes_cbc import AES_CBC

if __name__ == "__main__":
    cipher = AES_CBC()
    ciphertext = cipher.encrypt("This is a test of AES_CBC")
    print(f"The ciphertext is:{ciphertext}")
    plaintext = cipher.decrypt(ciphertext)
    print(f"The plaintext is:{plaintext}")
