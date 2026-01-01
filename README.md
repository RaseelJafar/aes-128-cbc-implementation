# AES-128 CBC From Scratch

This project implements **AES-128 encryption and decryption from scratch** in Python, including
**Cipher Block Chaining (CBC) mode**, **PKCS#7 padding**, and multiple **security analyses**.

The implementation avoids lookup tables and follows the AES algorithm step-by-step as discussed
in applied cryptography courses.

---

##  Features

- Full AES-128 implementation
  - SubBytes / InvSubBytes
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns
  - Key Expansion
  - AddRoundKey
- CBC mode encryption and decryption
- PKCS#7 padding and unpadding
- Interactive encryption/decryption runner
- Avalanche effect analysis
- Ciphertext error propagation analysis
- Image encryption and data-exposure visualization

---

