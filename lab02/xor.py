""" Autorem tego zadania jest Marta Piotrowska """

import os
import sys

"""Odczytywanie plików"""

def readOrig():
    try:
        with open("orig.txt", "r") as orig:
            return orig.read().lower()
    except FileNotFoundError:
        print("Nie znaleziono pliku z tekstem.")
        sys.exit(1)

def readPlain():
    try:
        with open("plain.txt", "r") as plain:
            return plain.read().lower().splitlines()
    except FileNotFoundError:
        print("Nie znaleziono pliku z tekstem.")
        sys.exit(1)

def readKey():
    try:
        with open("key.txt", "r") as key:
            return key.read().splitlines()
    except FileNotFoundError:
        print("Nie znaleziono pliku z kluczem.")
        sys.exit(1)

def readCrypto():
    try:
        with open("crypto.txt", "r") as crypto:
            return crypto.read().splitlines()
    except FileNotFoundError:
        print("Nie znaleziono pliku z tekstem zaszyfrowanym.")
        sys.exit(1)

"""Zapisywanie do plików"""

def writeCrypt(t):
    try:
        with open("crypto.txt", "w") as crypto:
            crypto.write(t)
    except OSError as e:
        print(f"Wystąpił błąd podczas zapisywania tekstu do pliku: {e}")
        sys.exit(1)

def writeDecrypt(t):
    try:
        with open("decrypt.txt", "w") as decrypt:
            decrypt.write(t)
    except OSError as e:
        print(f"Wystąpił błąd podczas zapisywania tekstu do pliku: {e}")
        sys.exit(1)

"""Funkcja -p: Przygotowanie i szyfrowanie"""

def pXor(key_lines, orig_text):
    line_len = 64
    plain_lines = [orig_text[i:i+line_len] for i in range(0, len(orig_text), line_len)]
    plain_lines = [line.ljust(line_len) for line in plain_lines]

    # Zapis plain.txt
    with open("plain.txt", "w") as plain:
        for line in plain_lines:
            plain.write(line + "\n")

    # Szyfrowanie i zapis crypto.txt
    with open("crypto.txt", "w") as crypto:
        for line, key in zip(plain_lines, key_lines):
            key = key.ljust(line_len)  # uzupełnij spacjami jeśli krótszy
            xor_result = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(line, key))
            crypto.write(xor_result.encode("latin1").hex() + "\n")

"""Funkcja -e: Deszyfrowanie"""

def eXor(key_lines, crypto_lines):
    decrypted_lines = []
    for line, key in zip(crypto_lines, key_lines):
        key = key.ljust(64)
        crypto_bytes = bytes.fromhex(line)
        decrypted = ''.join(chr(c ^ ord(k)) for c, k in zip(crypto_bytes, key))
        decrypted_lines.append(decrypted)
    writeDecrypt('\n'.join(decrypted_lines))

"""Funkcja -k: Kryptoanaliza z samych szyfrogramów"""

def kXor():
    crypto_lines = readCrypto()
    crypto_bytes = [bytes.fromhex(line) for line in crypto_lines]
    line_len = len(crypto_bytes[0])
    num_lines = len(crypto_bytes)

    # Inicjalizacja znanych pozycji spacjami i _
    guesses = [['_' for _ in range(line_len)] for _ in range(num_lines)]

    for i in range(num_lines):
        for j in range(i + 1, num_lines):
            xor = [a ^ b for a, b in zip(crypto_bytes[i], crypto_bytes[j])]
            for pos in range(line_len):
                if 65 <= xor[pos] <= 90 or 97 <= xor[pos] <= 122:
                    # Prawdopodobnie spacja i litera
                    guesses[i][pos] = ' '
                    guesses[j][pos] = '_'

    # Wynik
    result = '\n'.join([''.join(line) for line in guesses])
    writeDecrypt(result)

"""Obsługa opcji"""

if sys.argv[1] == "-p":
    print("Przygotowanie tekstu do przykładu działania")
    pXor(readKey(), readOrig())
elif sys.argv[1] == "-e":
    print("Szyfrowanie")
    eXor(readKey(), readCrypto())
elif sys.argv[1] == "-k":
    print("Kryptoanaliza")
    kXor()
sys.exit(0)
