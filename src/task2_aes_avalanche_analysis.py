import task2_aes
import os
import random

def flip_bit(data_bytes, bit_pos):
    """Flip a single bit in data_bytes at bit_pos (0-127) and return new bytes."""
    byte_index = bit_pos // 8
    bit_index = bit_pos % 8
    # Convert to list of ints to modify
    data_list = list(data_bytes)
    # Flip bit using XOR mask
    data_list[byte_index] ^= (1 << bit_index)
    return bytes(data_list)

def count_diff_bits(h1, h2):
    #Count how many bits differ between two byte arrays of equal length.
    num1 = int(h1, 16)
    num2 = int(h2, 16)

    # XOR and count bits that differ
    diff_bits = num1 ^ num2
    count_diff = bin(diff_bits).count("1")
    
    return count_diff

def random_128_bit():
    """Generate 16 random bytes (128 bits)."""
    return os.urandom(16)

def main():
    print("AES-CBC Avalanche Effect Analysis\n")

    # Generate random plaintext, key, and IV
    P1 = random_128_bit()
    K1 = random_128_bit()
    IV = random_128_bit()

    print(f"Original plaintext (P1): {P1.hex()}")
    print(f"Original key (K1):       {K1.hex()}")
    print(f"IV:                      {IV.hex()}\n")

    # Compute baseline ciphertext
    C1 = task2_aes.CBC_ENC(P1.hex(),IV.hex(),K1.hex())

    print("Running experiments (10 iterations each)...\n")
    print("Iteration | Flip Type    | Bit#   | Diff Bits | Diff %")
    print("----------------------------------------------------------------------------------------------------")


    for i in range(1, 11):
        # Plaintext bit flip
        bit_to_flip = random.randint(0, 127)
        P1_prime = flip_bit(P1, bit_to_flip)
        C2_plain = task2_aes.CBC_ENC(P1_prime.hex(), IV.hex(), K1.hex())

        # Remove IV (first 32 hex chars) before comparison
        C1_no_iv = C1[32:]
        C2_plain_no_iv = C2_plain[32:]

        same = (len(C2_plain_no_iv) == len(C1_no_iv))
        if not same:
            print(f" Iter {i} Plaintext: length mismatch ({len(C2_plain_no_iv)} vs {len(C1_no_iv)})")
        diff_plain = count_diff_bits(C1_no_iv, C2_plain_no_iv) if same else 0
        percentage_p  = (diff_plain / (len(C2_plain_no_iv) * 4) * 100) if same else 0.0

        print(f"{i:9} | Plaintext   | {bit_to_flip:4}  | {diff_plain:9} | {percentage_p:6.2f}%")

        # Key bit flip
        bit_to_flip_key = random.randint(0, 127)
        K1_prime = flip_bit(K1, bit_to_flip_key)
        C2_key = task2_aes.CBC_ENC(P1.hex(), IV.hex(), K1_prime.hex())

        C2_key_no_iv = C2_key[32:]      

        same2 = (len(C2_key_no_iv) == len(C1_no_iv))
        if not same2:
            print(f" Iter {i} Key: length mismatch ({len(C2_key_no_iv)} vs {len(C1_no_iv)})")
        diff_key = count_diff_bits(C1_no_iv, C2_key_no_iv) if same2 else 0
        percentage_k  = (diff_key / (len(C2_key_no_iv) * 4) * 100) if same2 else 0.0


        print(f"{i:9} | Key         | {bit_to_flip_key:4}  | {diff_key:9} | {percentage_k:6.2f}%")


    print(
    "\nAvalanche effect means a small change (one bit) in input/key\n"
    "results in large changes in the ciphertext.\n"
    "Encryption scheme to be secure, about 50% of the bits in ciphertext must change\n"
    "due to one bit flip in plaintext or key - Avalanche Effect.\n"
    "We see that the AES encryption scheme satisfy that -\n"
    "one bit flip in plaintext or key affect about 50% of the ciphertext bits.\n"
)




if __name__ == "__main__":
    main()
