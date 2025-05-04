""" Autorem tego zadania jest Marta Piotrowska """

from PIL import Image
import numpy as np
import hashlib
import os
import sys

block_size = 8  # bloki 8x8 pikseli

def load_image_grayscale(path):
    try:
        image = Image.open(path).convert("L")
        return np.array(image)
    except FileNotFoundError:
        print(f"Błąd: Nie znaleziono pliku '{path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Błąd podczas wczytywania obrazu: {e}")
        sys.exit(1)

def pad_image_to_block_size(img_array, block_size=8):
    height, width = img_array.shape
    new_height = ((height + block_size - 1) // block_size) * block_size
    new_width = ((width + block_size - 1) // block_size) * block_size
    padded = np.zeros((new_height, new_width), dtype=np.uint8)
    padded[:height, :width] = img_array
    return padded

def split_into_blocks(img_array, block_size=8):
    height, width = img_array.shape
    blocks = []
    for row in range(0, height, block_size):
        for col in range(0, width, block_size):
            block = img_array[row:row+block_size, col:col+block_size]
            blocks.append(block)
    return blocks

def hash_block(block):
    block_bytes = block.tobytes()
    digest = hashlib.sha1(block_bytes).digest()
    return digest

def expand_digest(digest, target_length=64):
    repeats = target_length // len(digest)
    remainder = target_length % len(digest)
    return (digest * repeats) + digest[:remainder]

def save_image_from_array(array, path):
    try:
        image = Image.fromarray(array)
        image.save(path)
        print(f"Zapisano obraz: {path}")
    except Exception as e:
        print(f"Błąd podczas zapisu obrazu: {e}")

img_array = load_image_grayscale("plain.bmp")

padded = pad_image_to_block_size(img_array)
height, width = padded.shape
blocks = split_into_blocks(padded)

# --- ECB ---
ecb_array = np.zeros_like(padded)
block_index = 0

for row in range(0, height, block_size):
    for col in range(0, width, block_size):
        block = blocks[block_index]
        digest = hash_block(block)
        new_block_bytes = expand_digest(digest, 64)
        new_block_array = np.frombuffer(new_block_bytes, dtype=np.uint8).reshape((8, 8))
        ecb_array[row:row+block_size, col:col+block_size] = new_block_array
        block_index += 1

save_image_from_array(ecb_array, "ecb_crypto.bmp")

# --- CBC ---
cbc_array = np.zeros_like(padded)
iv = os.urandom(20)
previous_block = iv
block_index = 0

for row in range(0, height, block_size):
    for col in range(0, width, block_size):
        block = blocks[block_index]
        block_bytes = block.tobytes()
        xor_block = bytes(a ^ b for a, b in zip(block_bytes, previous_block))
        digest = hashlib.sha1(xor_block).digest()
        new_block_bytes = expand_digest(digest, 64)
        new_block_array = np.frombuffer(new_block_bytes, dtype=np.uint8).reshape((8, 8))
        cbc_array[row:row+block_size, col:col+block_size] = new_block_array
        previous_block = digest
        block_index += 1

save_image_from_array(cbc_array, "cbc_crypto.bmp")
