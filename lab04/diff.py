""" Autorem tego zadania jest Marta Piotrowska """

def load_hashes(file):
    with open(file, "r") as f:
        return [line.strip().split(' *-')[0] for line in f if line.strip()]

def compare_hashes(h1, h2):
    n1 = int(h1, 16)
    n2 = int(h2, 16)
    bit_diff = bin(n1 ^ n2).count('1')
    total_bits = max(len(h1), len(h2)) * 4
    percent_diff = (bit_diff / total_bits) * 100
    return bit_diff, total_bits, percent_diff

def main():
    hashes = load_hashes("hash.txt")

    if len(hashes) < 2:
        print("Potrzeba co najmniej dwóch hashy w pliku.")
        return

    funkcjeHashowania = ['md5sum', 'sha1sum', 'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum', 'b2sum']
    with open("diff.txt", "w") as f:
        for i in range(0, len(hashes) - 1, 2):
            h1 = hashes[i]
            h2 = hashes[i + 1]
            bit_diff, total_bits, percent_diff = compare_hashes(h1, h2)
            result = (
                f"cat hash-.pdf personal.txt | " + funkcjeHashowania[int(i/2)] + "\n" +
                f"cat hash-.pdf personal_.txt | " + funkcjeHashowania[int(i/2)] + "\n" +
                h1 + "\n" + h2 + "\n" +
                f"Liczba różniących się bitów: {bit_diff} z {total_bits}, "
                f"procentowo: {percent_diff:.0f} %\n\n"
            )
            f.write(result)

if __name__ == "__main__":
    main()
