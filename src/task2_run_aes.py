import task2_aes

def menu():
    print("Please Select the Operation.")
    print("     1- Encrypt - enter E")
    print("     2- Decrypt - enter D")
    print("     3- Exit - enter X")

def readPlaintext():
    plaintext = input("Enter a plaintext in hexadecimal format: ")
    # Check validity
    try:
        #valid hexadecimal
        int(plaintext, 16)
        return plaintext
        
    except ValueError:
        print("Invalid hexadecimal!")
        return -1

def readCiphertext():
    ciphertext = input("Enter a ciphertext in hexadecimal format: ")
    # Check validity
    try:
        #valid hexadecimal
        int(ciphertext, 16)
        #check if the ciphertext is multiple of 128bits (multiple of 32 hexa digits)
        #the ciphertext should be multiple of 128bits due to the padding that used in encryption
        #but the plaintext can be in any length
        if(len(ciphertext) % 32 == 0):
            return ciphertext
        else:
            print("The ciphertext should be multiple of 128-bits, unlike the plaintext, due to the padding scheme thar used in encryption!")
            return -1
        
    except ValueError:
        print("Invalid hexadecimal!")
        return -1
    
def readKey(string):
    key = input(f"Enter a 128-bit {string} in hexadecimal format (32 hexa digits): ")
    # Check validity
    try:
        #valid hexadecimal
        int(key, 16)
        #check if it 32 digits - 128 bits
        if(len(key) == 32):
            return key
        else:
            print(f"The {string} is {len(key) * 4} bits not 128 !!")
            return -1
        
    except ValueError:
        print("Invalid hexadecimal!")
        return -1

def main():
    print("\n • Welcome to AES-128 Encryption and Decryption Program •")
    while True:
        menu()
        op = input().upper()
        if op == 'E':
            while True:
                plaintext = readPlaintext()
                if plaintext != -1:
                    break
            while True:
                key = readKey("key")
                if key != -1:
                    break
            while True:
                IV = readKey("IV")
                if IV != -1:
                    break
            ciphertext = task2_aes.CBC_ENC(plaintext,IV,key)
            print("\nCiphertext for the corresponding Plaintext in hexadecimal format is:")
            print(f"    0x{ciphertext}\n")
        
        elif op == 'D':
            while True:
                ciphertext = readCiphertext()
                if ciphertext != -1:
                    break
            while True:
                key = readKey("key")
                if key != -1:
                    break
            
            plaintext = task2_aes.CBC_Dec(ciphertext,key)
            print("\nPlaintext for the corresponding Ciphertext in hexadecimal format is:")
            print(f"    0x{plaintext}\n")
        
        elif op == 'X':
            print("\nExit from the Program ...")
            break
        else:
            print("Invalid choice, Try again !")
            
if __name__ == "__main__":
     main()