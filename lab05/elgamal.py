""" Autorem tego zadania jest Marta Piotrowska"""

import sys
import random

def modinv(a, m):
    """Oblicz odwrotność modularną a modulo m"""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('Brak odwrotności modularnej')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

def read_numbers(filename):
    try:
        with open(filename) as f:
            return [int(line.strip()) for line in f]
    except FileNotFoundError:
        print(f"Błąd: Plik '{filename}' nie został znaleziony.")
        sys.exit(1)
    except ValueError:
        print(f"Błąd: Plik '{filename}' zawiera nieprawidłowe dane.")
        sys.exit(1)

def write_numbers(filename, numbers):
    with open(filename, 'w') as f:
        for number in numbers:
            f.write(str(number) + '\n')

def generate_keys():
    p, g = read_numbers('elgamal.txt')
    x = random.randint(2, p - 2)    # private key
    y = pow(g, x, p)    # public key
    write_numbers('private.txt', [p, g, x])
    write_numbers('public.txt', [p, g, y])

def encrypt():
    p, g, y = read_numbers('public.txt')
    m = int(open('plain.txt').read().strip())
    if m >= p:
        print("Błąd: m >= p")
        return
    k = random.randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    write_numbers('crypto.txt', [a, b])

def decrypt():
    p, g, x = read_numbers('private.txt')
    a, b = read_numbers('crypto.txt')
    s = pow(a, x, p)
    s_inv = modinv(s, p)
    m = (b * s_inv) % p
    with open('decrypt.txt', 'w') as f:
        f.write(str(m))

def sign():
    p, g, x = read_numbers('private.txt')
    m = int(open('message.txt').read().strip())
    while True:
        k = random.randint(2, p - 2)
        if extended_gcd(k, p - 1)[0] == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((m - x * r) * k_inv) % (p - 1)
    write_numbers('signature.txt', [r, s])

def verify():
    p, g, y = read_numbers('public.txt')
    m = int(open('message.txt').read().strip())
    r, s = read_numbers('signature.txt')
    v1 = pow(g, m, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    result = 'T' if v1 == v2 else 'N'
    with open('verify.txt', 'w') as f:
        f.write(result)
    print(result)

def main():
    if len(sys.argv) != 2:
        print("Użycie: elgamal.py -k|-e|-d|-s|-v")
        return
    option = sys.argv[1]
    if option == '-k':
        generate_keys()
    elif option == '-e':
        encrypt()
    elif option == '-d':
        decrypt()
    elif option == '-s':
        sign()
    elif option == '-v':
        verify()
    else:
        print("Nieznana opcja")

if __name__ == '__main__':
    main()
