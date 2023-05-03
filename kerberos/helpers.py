import string
import time
import hashlib

alphabet = list(string.ascii_lowercase)
numbers = list('123456789')
SERVER_ADDRESS = '192.168.56.1'  # change this to your server's IP address


def encrypt(plaintext, key):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            if char.isupper():
                ciphertext += chr((ord(char) + key - 65) % 26 + 65)
            else:
                ciphertext += chr((ord(char) + key - 97) % 26 + 97)
        elif char.isdigit():
            ciphertext += str((int(char) + key) % 10)
        else:
            ciphertext += char
    return ciphertext


def decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.isupper():
                plaintext += chr((ord(char) - key - 65) % 26 + 65)
            else:
                plaintext += chr((ord(char) - key - 97) % 26 + 97)
        elif char.isdigit():
            plaintext += str((int(char) - key) % 10)
        else:
            plaintext += char
    return plaintext


def hash_password(password):
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')

    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password_bytes).hexdigest()

    return hashed_password


def request_animation(is_forwarding):
    input("Press Enter to send...")
    str = '###'
    if not is_forwarding:
        str = '<=== ' + str
        print(str, end='')
    for _ in range(0, 5):
        time.sleep(0.5)
        print(f"\r{str}", end=' ')
        str = str + '###'
    if is_forwarding:
        print('===>', end=' ')
    print('\n')
