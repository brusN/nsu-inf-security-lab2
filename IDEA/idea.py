import gmpy2
import hashlib

# Theory and IDEA step-by-step description: https://intuit.ru/studies/courses/13837/1234/lecture/31198?page=7


# Modular mul func
def _mul(x, y):
    assert 0 <= x <= 0xFFFF
    assert 0 <= y <= 0xFFFF

    if x == 0:
        x = 0x10000
    if y == 0:
        y = 0x10000

    r = (x * y) % 0x10001

    if r == 0x10000:
        r = 0

    assert 0 <= r <= 0xFFFF
    return r


# Check https://intuit.ru/studies/courses/13837/1234/lecture/31198?page=7 on "7.7.2 Description IDEA"
def _KA_layer(x1, x2, x3, x4, round_keys):
    # Subblocks size check
    assert 0 <= x1 <= 0xFFFF
    assert 0 <= x2 <= 0xFFFF
    assert 0 <= x3 <= 0xFFFF
    assert 0 <= x4 <= 0xFFFF

    z1, z2, z3, z4 = round_keys[0:4]

    # Subkeys size check
    assert 0 <= z1 <= 0xFFFF
    assert 0 <= z2 <= 0xFFFF
    assert 0 <= z3 <= 0xFFFF
    assert 0 <= z4 <= 0xFFFF

    y1 = _mul(x1, z1)  # 1. Modular mul subblock x1, subkey z1
    y2 = (x2 + z2) % 0x10000  # 2. Modular add subblock x2, subkey z2
    y3 = (x3 + z3) % 0x10000  # 3. Modular add subblock x3, subkey z3
    y4 = _mul(x4, z4)  # 4. Modular mul subblock x4, subkey z4

    return y1, y2, y3, y4


# Check https://intuit.ru/studies/courses/13837/1234/lecture/31198?page=7 on "7.7.2 Description IDEA"
def _MA_layer(y1, y2, y3, y4, round_keys):
    # Subblocks size check
    assert 0 <= y1 <= 0xFFFF
    assert 0 <= y2 <= 0xFFFF
    assert 0 <= y3 <= 0xFFFF
    assert 0 <= y4 <= 0xFFFF

    z5, z6 = round_keys[4:6]

    # Subkeys size check
    assert 0 <= z5 <= 0xFFFF
    assert 0 <= z6 <= 0xFFFF

    p = y1 ^ y3  # 5. Xor y1 and y3
    q = y2 ^ y4  # 6. Xor y2 and y4

    s = _mul(p, z5)  # 7. Mul result of 5th step and 5th subkey
    t = _mul((q + s) % 0x10000, z6)  # 8-9. Modular add results of 6-7 steps and mul result 8th step with 6th subkey
    u = (s + t) % 0x10000  # 10. Modular add results 7-9th steps

    # 11-14th steps
    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4


class IDEA:
    def __init__(self, key):
        self._expand_key = []
        self._encrypt_key = None
        self._decrypt_key = None
        self.expand_key(key)
        self.get_encrypt_key()
        self.get_decrypt_key()

    def expand_key(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 128
        for i in range(6 * 8 + 4):
            self._expand_key.append((key >> (112 - 16 * (i % 8))) % 0x10000)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % modulus
        return self._expand_key

    def get_encrypt_key(self):
        keys = []
        for i in range(9):
            round_keys = self._expand_key[6 * i:6 * (i + 1)]
            keys.append(tuple(round_keys))
        self._encrypt_key = tuple(keys)

    def get_decrypt_key(self):
        keys = [0] * 52
        for i in range(9):
            if i == 0:
                for j in range(6):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[j] = 0
                        else:
                            keys[j] = gmpy2.invert(self._encrypt_key[8 - i][j],
                                                   65537)
                    elif j == 1 or j == 2:
                        keys[j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
                    else:
                        keys[j] = self._encrypt_key[7 - i][j]
            elif i < 8:
                for j in range(6):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[i * 6 + j] = 0
                        else:
                            keys[i * 6 + j] = gmpy2.invert(
                                self._encrypt_key[8 - i][j], 65537)
                    elif j == 1 or j == 2:
                        keys[i * 6 + 3 -
                             j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
                    else:
                        keys[i * 6 + j] = self._encrypt_key[7 - i][j]
            else:
                for j in range(4):
                    if j == 0 or j == 3:
                        if self._encrypt_key[8 - i][j] == 0:
                            keys[i * 6 + j] = 0
                        else:
                            keys[i * 6 + j] = gmpy2.invert(
                                self._encrypt_key[8 - i][j], 65537)
                    else:
                        keys[i * 6 +
                             j] = (65536 - self._encrypt_key[8 - i][j]) % 65536
        tmp = []
        for i in range(9):
            round_keys = keys[6 * i:6 * (i + 1)]
            tmp.append(tuple(round_keys))
        self._decrypt_key = tuple(tmp)

    def enc_dec(self, plaintext, flag):
        # Block size check
        assert 0 <= plaintext < (1 << 64)

        # Splitting block on four 16-bit subblocks
        x1 = (plaintext >> 48) & 0xFFFF
        x2 = (plaintext >> 32) & 0xFFFF
        x3 = (plaintext >> 16) & 0xFFFF
        x4 = plaintext & 0xFFFF

        if flag == 0:
            key = self._encrypt_key
        else:
            key = self._decrypt_key

        # First 8 IDEA steps
        for i in range(8):
            round_keys = key[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            x2, x3 = x3, x2

        # Last 9th step
        y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, key[8])

        # Combine result blocks
        ciphertext = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
        return ciphertext


def calcFileHash(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def main():
    key = 0x2BD6459F82C5B300952C49104881FF48  # 128-bit key
    my_IDEA = IDEA(key)

    # Encrypt file
    encrypted_file = open('../files/encrypted_file.txt', 'wb+')
    try:
        with open('../files/testfile.txt', 'rb') as file:
            block = int.from_bytes(file.read(8), "big")
            while block:
                encryptedBlock = my_IDEA.enc_dec(block, 0)
                encryptedBytes = encryptedBlock.to_bytes(8, 'big')
                encrypted_file.write(encryptedBytes)
                block = int.from_bytes(file.read(8), "big")
    except IOError:
        print('Error while opening input file!')
        exit(1)

    encrypted_file.close()

    # Decrypt file
    decrypted_file = open('../files/decrypted_file.txt', 'wb+')
    try:
        with open('../files/encrypted_file.txt', 'rb') as encrypted_file:
            block = int.from_bytes(encrypted_file.read(8), "big")
            while block:
                decryptedBlock = my_IDEA.enc_dec(block, 1)
                decryptedBytes = int(decryptedBlock).to_bytes(8, 'big')
                decrypted_file.write(decryptedBytes)
                block = int.from_bytes(encrypted_file.read(8), "big")
    except IOError:
        print('Error while opening encrypted file!')
        exit(1)

    decrypted_file.close()

    # Calc hash of encrypted file
    print('Hash >>> ' + calcFileHash('../files/encrypted_file.txt'))


if __name__ == '__main__':
    main()
