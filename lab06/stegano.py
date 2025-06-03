"""Autorem tego zadania jest Marta Piotrowska"""
import sys
import re
import os

# === Konwersje ===
def hex_to_bits(hex_string):
    try:
        return ''.join(f'{int(c, 16):04b}' for c in hex_string.strip())
    except ValueError:
        raise ValueError("Nieprawidłowy format wiadomości heksadecymalnej")


def bits_to_hex(bits):
    try:
        bits = bits[:len(bits) - len(bits) % 4]
        return ''.join(hex(int(bits[i:i + 4], 2))[2:] for i in range(0, len(bits), 4))
    except ValueError:
        raise ValueError("Nieprawidłowy format bitów")


# === Funkcje steganograficzne ===

# dodawanie spacji na końcu linii,
# jeśli bit = 1, dodaje spację na końcu linii

def embed_mode_1(message_bits, lines):
    if len(message_bits) > len(lines):
        raise ValueError("Za mało linii w nośniku.")

    result = []
    for i, line in enumerate(lines):
        line = line.rstrip('\n').rstrip(' ')
        if i < len(message_bits) and message_bits[i] == '1':
            line += ' '
        result.append(line + '\n')
    return result


def extract_mode_1(lines):
    return ''.join('1' if line.rstrip('\n').endswith(' ') else '0' for line in lines)

# zastępowanie pojedynczych spacji podwójnymi
def embed_mode_2(message_bits, lines):
    text = re.sub(r' {2,}', ' ', ''.join(lines))
    space_positions = [m.start() for m in re.finditer(r' ', text)]

    if len(message_bits) > len(space_positions):
        raise ValueError("Za mało pojedynczych spacji.")

    text = list(text)
    for i, bit in enumerate(message_bits):
        if bit == '1':
            text[space_positions[i]] = '  '
    return ''.join(text)

def extract_mode_2(lines):
    text = ''.join(lines)
    bits = []
    i = 0
    while i < len(text):
        if text[i] == ' ':
            if i + 1 < len(text) and text[i + 1] == ' ':
                bits.append('1')
                i += 2
            else:
                bits.append('0')
                i += 1
        else:
            i += 1
    return ''.join(bits)

# dodawanie fałszywych literówek w atrybutach HTML
def embed_mode_3(message_bits, lines):
    text = ''.join(lines)
    text = re.sub(r'margin-botom', 'margin-bottom', text)
    text = re.sub(r'lineheight', 'line-height', text)

    paragraph_matches = list(re.finditer(r'<p[^>]*style="[^"]*">', text))
    if len(message_bits) > len(paragraph_matches):
        raise ValueError("Za mało akapitów z stylem.")

    for i, bit in enumerate(message_bits):
        match = paragraph_matches[i]
        original = match.group(0)
        if bit == '0':
            new_style = original.replace('margin-bottom', 'margin-botom')
        else:
            new_style = original.replace('line-height', 'lineheight')
        text = text[:match.start()] + new_style + text[match.end():]
    return text


def extract_mode_3(lines):
    text = ''.join(lines)
    bits = []
    for match in re.finditer(r'<p[^>]*style="[^"]*">', text):
        if 'margin-botom' in match.group(0):
            bits.append('0')
        elif 'lineheight' in match.group(0):
            bits.append('1')
    return ''.join(bits)

# manipulowanie znacznikami FONT
def embed_mode_4(message_bits, lines):
    text = ''.join(lines)
    text = re.sub(r'<FONT></FONT>|<FONT\s*[^>]*>\s*</FONT>', '', text, flags=re.IGNORECASE)

    matches = list(re.finditer(r'<FONT[^>]*>', text, flags=re.IGNORECASE))
    if len(message_bits) > len(matches):
        raise ValueError("Za mało znaczników FONT.")

    offset = 0
    for i, bit in enumerate(message_bits):
        match = matches[i]
        start = match.start() + offset
        end = match.end() + offset
        replacement = match.group(0) + ('</FONT>' + match.group(0) if bit == '1' else '</FONT><FONT>')
        text = text[:start] + replacement + text[end:]
        offset += len(replacement) - (end - start)
    return text


def extract_mode_4(lines):
    text = ''.join(lines)
    pattern = re.compile(r'(<FONT[^>]*>)(</FONT><FONT[^>]*>|</FONT><FONT>)', re.IGNORECASE)
    bits = []
    i = 0
    while i < len(text):
        match = pattern.search(text, i)
        if not match:
            break
        # sprawdź, czy w grupie 2 występuje '</FONT><FONT>' czy '</FONT><FONT[^>]*>'
        if '</FONT><FONT>' in match.group(2):
            bits.append('0')
        else:
            bits.append('1')
        i = match.end()
    return ''.join(bits)



def process_file(action, mode):
    """
    Przetwarza pliki steganograficzne.

    action: '-e' (encode) lub '-d' (decode)
    mode: '-1', '-2', '-3' lub '-4' - tryb steganografii
    """

    embed_funcs = {
        '-1': embed_mode_1,
        '-2': embed_mode_2,
        '-3': embed_mode_3,
        '-4': embed_mode_4
    }

    extract_funcs = {
        '-1': extract_mode_1,
        '-2': extract_mode_2,
        '-3': extract_mode_3,
        '-4': extract_mode_4
    }

    valid_actions = {'-e', '-d'}

    if action not in valid_actions:
        raise ValueError(f"Nieznana akcja: {action}. Dostępne akcje: -e, -d")

    if mode not in embed_funcs:
        raise ValueError(f"Nieznany tryb: {mode}. Dostępne tryby: -1, -2, -3, -4")

    cover_file = 'cover.html'  # plik nośnika
    message_file = 'mess.txt'  # plik z wiadomością (dla -e)
    watermark_file = 'watermark.html'  # plik wyjściowy (dla -e)
    detect_file = 'detect.txt'  # plik z wyodrębnioną wiadomością (dla -d)

    if not os.path.exists(cover_file):
        raise FileNotFoundError(f"Plik {cover_file} nie istnieje")

    if action == '-e':
        if not os.path.exists(message_file):
            raise FileNotFoundError(f"Plik {message_file} nie istnieje")

        # Enkodowanie
        try:
            with open(message_file, 'r', encoding='utf-8') as f:
                hex_message = f.read().strip()
            with open(cover_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            message_bits = hex_to_bits(hex_message)

            # Dodaj znak końca (ASCII 127 - DEL)
            end_marker = format(127, '08b')
            message_bits = message_bits + end_marker

            output = embed_funcs[mode](message_bits, lines)

            with open(watermark_file, 'w', encoding='utf-8') as f:
                if isinstance(output, list):
                    f.writelines(output)
                else:
                    f.write(output)
            print(f"[INFO] Wiadomość zanurzona w {watermark_file}")
        except UnicodeDecodeError:
            raise ValueError(f"Nie można odczytać pliku {message_file} - nieprawidłowe kodowanie")


    elif action == '-d':
        # Dekodowanie
        try:
            # Używamy watermark.html zamiast cover.html do dekodowania
            with open(watermark_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            extracted_bits = extract_funcs[mode](lines)

            # Upewnij się, że mamy string
            if not isinstance(extracted_bits, str):
                extracted_bits = ''.join(map(str, extracted_bits))

            # Znajdź koniec wiadomości (DEL - 01111111)
            del_marker = format(127, '08b')  # '01111111'
            bits_to_process = ""

            # Przetwarzaj po 8 bitów
            i = 0
            while i + 8 <= len(extracted_bits):
                chunk = extracted_bits[i:i + 8]
                # Jeśli znaleźliśmy marker końca, przerywamy
                if chunk == del_marker:
                    break
                bits_to_process += chunk
                i += 8

            # Konwertuj bity na format heksadecymalny
            hex_message = bits_to_hex(bits_to_process)

            with open(detect_file, 'w', encoding='utf-8') as f:
                f.write(hex_message)
            print(f"[INFO] Wiadomość wyodrębniona do {detect_file}")
        except UnicodeDecodeError:
            raise ValueError(f"Nie można odczytać pliku {watermark_file} - nieprawidłowe kodowanie")




if __name__ == "__main__":
    try:
        if len(sys.argv) < 3:
            raise ValueError("Za mało argumentów. Wymagane: akcja (-e/-d) i tryb (-1/-2/-3/-4)")

        if len(sys.argv) > 3:
            raise ValueError("Podano zbyt wiele argumentów!")

        action = sys.argv[1]
        mode = sys.argv[2]

        process_file(action, mode)

    except ValueError as e:
        print(f"[BŁĄD] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[BŁĄD] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[BŁĄD] Nieoczekiwany błąd: {e}")
        sys.exit(1)
