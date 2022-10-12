# import codecs
import codecs


# Key scheduling algorithm
def ksa(key):
    key_length = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_length]) % 256
        s[i], s[j] = s[j], s[i]
    return s


# Pseudo random generation algorithm
def prga(s):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        yield k


# Takes the encryption key to get the keystream using PRGA, return object is a generator
def get_keystream(key):
    S = ksa(key)
    return prga(S)


def encrypt_logic(key, text):
    key = [ord(c) for c in key]
    keystream = get_keystream(key)
    res = []
    for c in text:
        val = ("%02X" % (c ^ next(keystream)))  # XOR and taking hex
        res.append(val)
    return ''.join(res)


def encrypt(key, plaintext):
    plaintext = [ord(c) for c in plaintext]
    return encrypt_logic(key, plaintext)


def decrypt(key, encrypted_text):
    encrypted_text = codecs.decode(encrypted_text, 'hex_codec')
    res = encrypt_logic(key, encrypted_text)
    return codecs.decode(res, 'hex_codec').decode('utf-8')


def main():
    print('Change mode:')
    print('1. Encrypt')
    print('2. Decrypt')

    mode = int(input())
    if mode == 1:
        print('Plain text: ')
        plain_text = input()
        print('Secret key: ')
        secret_key = input()
        encrypted = encrypt(secret_key, plain_text)
        print('Encrypted >> ' + encrypted)
    elif mode == 2:
        print('Encrypted text: ')
        encrypted_text = input()
        print('Secret key: ')
        secret_key = input()
        decrypted = decrypt(secret_key, encrypted_text)
        print('Decrypted >> ' + decrypted)
    else:
        print('Wrong mode input!')
        exit(1)


if __name__ == '__main__':
    main()
