import task2_aes
from PIL import Image
import numpy as np
import os


# Load and convert to 8-bit grayscale (L)
img = Image.open("C:\\Users\\Mohammed Sa'deh\\Desktop\\Crypto\\Task2\\image.bmp").convert("L")
w, h = img.size
pixels = img.tobytes()           # raw grayscale bytes, length = w*h


key = os.urandom(16) 
IV = os.urandom(16)

ciphertext = task2_aes.CBC_ENC(pixels.hex(),IV.hex(), key.hex())


#Trudy sniffing the ciphertext, and attempt to convert it to an image
#skip the first block - IV
ciphertext = bytes.fromhex(ciphertext )
ciphertext = ciphertext[16:]
rows = len(ciphertext) // w
ct_view = ciphertext[:rows * w]                 # drop any trailing partial row
img_ct = Image.frombytes("L", (w, rows), ct_view)
img_ct.save("ciphertext_visual_cbc.png")