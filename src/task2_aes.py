##############################################################################
#MixColumns/InvMixColumns
def GF_Mul(byte):
    # Multiply byte by 2 in GF(2^8)
    shifted = int(byte) << 1
    if (int(byte) & 0x80):  # if highest bit set
        shifted ^= 0x1b  # XOR with AES irreducible polynomial
    return shifted & 0xFF 

def multiply(byte, factor):
    # Multiply byte by 1, 2, or 3 as needed
    byte = int(byte,16)
    if factor == 1:
        return byte
    elif factor == 2:
        return GF_Mul(byte)
    elif factor == 3:
        return GF_Mul(byte) ^ byte
    elif factor == 9:
        # 9 = 8 + 1 = (((byte*2)*2)*2) ^ byte
        return GF_Mul(GF_Mul(GF_Mul(byte))) ^ byte # 8 + 1
    elif factor == 11:
        # 11 = 9 + 2
        return GF_Mul(GF_Mul(GF_Mul(byte))) ^ GF_Mul(byte) ^ byte # 8 + 2 + 1
    elif factor == 13:
        # 13 = 11 + 2
        return GF_Mul(GF_Mul(GF_Mul(byte))) ^ GF_Mul(GF_Mul(byte)) ^ byte # 8 + 4 + 1
    elif factor == 14:
        # 14 = 13 + 1
        return GF_Mul(GF_Mul(GF_Mul(byte))) ^ GF_Mul(GF_Mul(byte)) ^ GF_Mul(byte) # 8 + 4 + 2

def mix_single_column(col):
    # column [c0, c1, c2, c3]
    c0, c1, c2, c3 = col
    r0 = multiply(c0, 2) ^ multiply(c1, 3) ^ multiply(c2, 1) ^ multiply(c3, 1)
    r1 = multiply(c0, 1) ^ multiply(c1, 2) ^ multiply(c2, 3) ^ multiply(c3, 1)
    r2 = multiply(c0, 1) ^ multiply(c1, 1) ^ multiply(c2, 2) ^ multiply(c3, 3)
    r3 = multiply(c0, 3) ^ multiply(c1, 1) ^ multiply(c2, 1) ^ multiply(c3, 2)
    return [r0, r1, r2, r3]

def inv_mix_single_column(col):
    c0, c1, c2, c3 = col
    r0 = multiply(c0, 14) ^ multiply(c1, 11) ^ multiply(c2, 13) ^ multiply(c3, 9)
    r1 = multiply(c0, 9)  ^ multiply(c1, 14) ^ multiply(c2, 11) ^ multiply(c3, 13)
    r2 = multiply(c0, 13) ^ multiply(c1, 9)  ^ multiply(c2, 14) ^ multiply(c3, 11)
    r3 = multiply(c0, 11) ^ multiply(c1, 13) ^ multiply(c2, 9)  ^ multiply(c3, 14)
    return [r0, r1, r2, r3]


def mix_columns(state):
    # state is a 4x4 matrix of bytes, column-major order
    for i in range(4):
        col = [state[row][i] for row in range(4)]
        mixed = mix_single_column(col)
        for row in range(4):
            state[row][i] = mixed[row]
    converted_hexa = [[f"{num:02X}" for num in row] for row in state]
    return converted_hexa

def inv_mix_columns(state):
    temp = state.copy()
    for i in range(4):
        col = [temp[row][i] for row in range(4)]
        mixed = inv_mix_single_column(col)
        for row in range(4):
            temp[row][i] = mixed[row]
    converted_hexa = [[f"{num:02X}" for num in row] for row in temp]
    return converted_hexa

######################################################################################################
#Add round key

def add_round_key(state, round_key):
    #print(state)
    #XOR the state with the round key 
    for r in range(4):
        for c in range(4):
            value1 = int(state[r][c], 16)
            value2 = int(round_key[c][r],16)
            x = value1 ^ value2
            state[r][c] = format(x, '02x')
    return state



################## SubByte ---- S-Box ############################################################################
#### Inversion using EEA - which find the multiplicative inverse of a byte (polynomial in GF(2^8)) 

#functions for the basic operations in GF(2^8) - add/sub , mul, long division 
#addition/subtraction in GF(2)
def add(p,q):
    result = [0] * max(len(p),len(q))
    if len(p) != len(q):
        if len(p) > len(q):
            while len(q) < len(p):
                q.insert(0,0)
        else:
            while len(p) < len(q):
                p.insert(0,0)
    for i in range(max(len(p),len(q))):
        result[i] = int(p[i]) ^ int(q[i])
    
    #result = ''.join(map(str, result))
    return result

#find the degree of the polynomial 
def degree(p):
    degree = 0
    for i in range(len(p)):
        if int(p[i]) == 1:
            degree = len(p) - i - 1
            break
    return degree

def mul(p,q):
    result = [0] * (degree(p) + degree(q) + 1 )
    #temp = [0] * (degree(p) + degree(q) + 1)
    if degree(p) > degree(q):
        X = p
        Y = q
    else:
        X = q
        Y = p
    
    i = len(Y) - 1
    while i >= 0:
        if(Y[i] == 1):
            temp = X.copy()
            while len(temp) < (degree(p) + degree(q) + 1):
                temp.insert(0,0)
            list = [0] * (len(Y) - i - 1)
            temp = temp + list
            if len(temp) > (degree(p) + degree(q) + 1):
                temp = temp[len(temp) - (degree(p) + degree(q) + 1 ):]
            for j in range(len(result)):
                result[j] = result[j] ^ temp[j]
        i-=1

    index_of_first_one = next((i for i, x in enumerate(result) if x == 1), None)
    if index_of_first_one is not None:
        result = result[index_of_first_one:]
    return result


def long_div(p,d):
    #find p/d
    r = p
    q = [0] * 8
    
    binary_str = ''.join(str(bit) for bit in d)
    decimal_value = int(binary_str, 2)

    if decimal_value == 1:
        return(r,q)

    while degree(r) >= degree(d) and not all(x==0 for x in r):
        temp = [0] * 8
        temp[len(temp) - 1 - (degree(r) - degree(d))] = 1
        q = add(q,temp)
        t = mul(temp,d)
        r = add(r,t)
    
    return (q,r)



def inversion(A):
    #A is a byte in hexadecimal
    decimal_value = int(A, 16)

    binary_str = format(decimal_value, '08b')
    A_binary = [int(bit) for bit in binary_str]

    if A == '00':
        return '00'
    
    q=[[0,0,0,0,0,0,0,0]]
    r=[[1,0,0,0,1,1,0,1,1]]
    r.append(A_binary)
    s = [[0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0]]
    t = [[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,1]]

    i = 2
    while True:
        Q,R = long_div(r[i-2],r[i-1])
        q.append(Q)
        r.append(R)
        binary_str = ''.join(str(bit) for bit in R)
        R_dec = int(binary_str, 2)
        if R_dec == 0:
            break
        S = add(s[i-2], mul(s[i-1],q[i-1]))
        T = add(t[i-2], mul(t[i-1],q[i-1]))

        s.append(S)
        t.append(T)
        i+=1
    
    binary_str = ''.join(str(bit) for bit in r[i-1])
    gcd = int(binary_str, 2)
    if gcd != 1:
        print(f"{A} has no inverse in mod {r[0]}")
        return -1
    
    else:
        binary_str = ''.join(str(bit) for bit in t[i-1])
        decimal_value = int(binary_str, 2)
        hex_str = format(decimal_value, 'X').zfill((len(t[i-1]) + 3) // 4)
        return hex_str

#### Affine Mapping
def Affine_Mapping(A, Enc):
    #convert hexadecimal to list of binary
    decimal_value = int(A, 16)
    binary_str = format(decimal_value, f'0{len(A) * 4}b')
    binary_list = [int(bit) for bit in binary_str]
    binary_list = binary_list[::-1] 

    if(Enc):
    #constant matrices for Affine Mapping - Encryption
        c1 = [[1,0,0,0,1,1,1,1],
            [1,1,0,0,0,1,1,1],
            [1,1,1,0,0,0,1,1],
            [1,1,1,1,0,0,0,1],
            [1,1,1,1,1,0,0,0],
            [0,1,1,1,1,1,0,0],
            [0,0,1,1,1,1,1,0],
            [0,0,0,1,1,1,1,1]]

        c2 = [1,1,0,0,0,1,1,0]

    else:
    #constant matrices for Affine Mapping - Decryption
        c1 = [[0,0,1,0,0,1,0,1],
            [1,0,0,1,0,0,1,0],
            [0,1,0,0,1,0,0,1],
            [1,0,1,0,0,1,0,0],
            [0,1,0,1,0,0,1,0],
            [0,0,1,0,1,0,0,1],
            [1,0,0,1,0,1,0,0],
            [0,1,0,0,1,0,1,0]]

        c2 = [1,0,1,0,0,0,0,0]

    b = [0] * 8

    for i in range(len(binary_list)):
        for j in range(len(c1[i])):
            b[i] = b[i] ^ (c1[i][j] * binary_list[j])
        b[i] = b[i] ^ c2[i]
    
    b = b[::-1] 
    binary_str = ''.join(str(bit) for bit in b)
    decimal_value = int(binary_str, 2)
    hex_str = format(decimal_value, 'X').zfill((len(b) + 3) // 4)

    return hex_str

    
##### SubByte ----- S-Box ########
def S_Box(A):
    #A is a hexadecimal byte
    c = inversion(A)
    return (Affine_Mapping(c,True))

def Inv_S_Box(A):
    #A is a hexadecimal byte
    c = Affine_Mapping(A,False)
    return (inversion(c))

def SubByte(state):
    #s = [[cell[2:].upper().zfill(2) for cell in row] for row in state]
    
    newState = []
    for i in range(len(state)):
        g = []
        for j in range(len(state[i])):
            g.append(S_Box(state[i][j]))
        newState.append(g)
    return newState

def InvSubByte(state):
    #s = [[cell[2:].upper().zfill(2) for cell in row] for row in state]
    
    newState = []
    for i in range(len(state)):
        g = []
        for j in range(len(state[i])):
            g.append(Inv_S_Box(state[i][j]))
        newState.append(g)
    return newState

#########################################################################################################################3
#key expansion 

def RC(round_idx):
    # Generate RC value for given round index (1-based)
    if round_idx == 0:
        return 0
    RC_val = 1
    for _ in range(round_idx - 1):
        RC_val = GF_Mul(RC_val)
    return RC_val


def rot_word(word):
    # Rotate 4-byte word left by 1 byte
    return word[1:] + word[:1]

def sub_word(word):
    return [int(S_Box(f"{b:02X}"), 16) for b in word]




def key_expansion(key):
    key_bytes = [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
    key_words = 4      # Number of 32-bit words in the key 
    block_words = 4    # Number of 32-bit words in block
    rounds = 10        # Number of rounds for AES-128

    # Split the key into 4 words
    expanded_keys = [key_bytes[4*i:4*(i+1)] for i in range(key_words)]

    for i in range(key_words, block_words * (rounds + 1)):
        temp = expanded_keys[i - 1].copy()

        if i % key_words == 0:
            temp = rot_word(temp)            # Rotate
            temp = sub_word(temp)            # Substitute bytes with
            temp[0] ^= RC(i // key_words) # XOR with RC

        # XOR with word block words positions before
        word_before = expanded_keys[i - key_words]
        new_word = [word_before[j] ^ temp[j] for j in range(4)]
        expanded_keys.append(new_word)

    return expanded_keys

def _rot_left_row(row, k):
    """Rotate a length-4 list left by k (0..3) in-place."""
    k %= 4
    if k == 0:
        return row
    # manual rotate to avoid list comprehensions
    tmp = [0, 0, 0, 0]
    i = 0
    while i < 4:
        tmp[i] = row[(i + k) % 4]
        i += 1
    i = 0
    while i < 4:
        row[i] = tmp[i]
        i += 1
    return row

def _rot_right_row(row, k):
    
    return _rot_left_row(row, 4 - (k % 4))

def ShiftRows(state):
  
    _rot_left_row(state[1], 1)
    _rot_left_row(state[2], 2)
    _rot_left_row(state[3], 3)
    return state

def InvShiftRows(state):
   
    _rot_right_row(state[1], 1)
    _rot_right_row(state[2], 2)
    _rot_right_row(state[3], 3)
    return state

def hexaPlaintext_To_state(A):
    b = []
    #divide it to bytes
    i = 0
    while i < len(A):
        b.append(f'{A[i]}{A[i+1]}')
        i+=2

    list = []
    state = []
    for i in range(4):
        for j in range(4):
            list.append(b[j*4 + i])
            # print(f'state[{i}][{j}] = b[{((j*4) + i)}] = {state[i][j]} = {b[j*4 + i]}')
        state.append(list)
        list = []
    
    converted_hex = [[f"{int(cell, 16):02X}" for cell in row] for row in state]
    return converted_hex

def state_to_hexa(state):
    p = [0] * (len(state) * len(state))

    for i in range(len(state)):
        for j in range(len(state)):
            p[i + (4*j)] = state[i][j]
    combined = ''.join(p)
    return combined

def Enc(A, key):
    #A is a hexadecimal plaintext
    state = hexaPlaintext_To_state(A)
    K = key_expansion(key)
    K_hex = [[f"{num:02x}" for num in row] for row in K]
    #pre-round transformation 
    state = add_round_key(state,K_hex[0:4])

    for i in range(9):
        state = SubByte(state)
        state = ShiftRows(state)
        state = mix_columns(state)
        start = i * 4 + 4 
        state = add_round_key(state, K_hex[start:start+4])
    
    state = SubByte(state)
    state = ShiftRows(state)
    state =add_round_key(state,K_hex[40:44])

    return state_to_hexa(state)


def key_To_state(k):
    list = []
    state = []
    for i in range(4):
        for j in range(4):
            list.append(k[j*4 + i])
        state.append(list)
        list = []
    
    converted_hex = [[f"{int(cell, 16):02X}" for cell in row] for row in state]
    return converted_hex

def Dec(C, key):
    #C is a hexadecimal ciphertext
    state = hexaPlaintext_To_state(C)
    K = key_expansion(key)
    K_hex = [[f"{num:02x}" for num in row] for row in K]
    #print(K_hex[0:4])
    #pre-round transformation 
    state = add_round_key(state,K_hex[40:44])


    for i in range(9):
        state = InvShiftRows(state)
        state = InvSubByte(state)
        start = (36 - (i * 4)) 
        state = add_round_key(state, K_hex[start:start+4])
        state = inv_mix_columns(state)

    #round 10
    state = InvShiftRows(state)
    state = InvSubByte(state)
    state =add_round_key(state,K_hex[0:4])

    return state_to_hexa(state)



###############################################################################################
#padding the message using PKCS7 padding scheme
def padding(m):
    #the input is the message in hexadecimal
    
    #find the number of bytes in the last block
    n = len(m)/2 % 16 
    #find the number of bytes to be added for padding
    num_of_bytes = int(16 - n) 
    hexadecimal = format(num_of_bytes, 'X')

    if num_of_bytes != 16:
        hexadecimal = '0' + hexadecimal

    for i in range(num_of_bytes):
        m = m+hexadecimal

    return m


#the input is plaintext and IV in hexadecimal
def CBC_ENC(plaintext, IV, key):
    #padding the message using PKCS7 padding scheme
    plaintext = padding(plaintext)

    plaintext_binary = bin(int(plaintext, 16))[2:].zfill(len(plaintext) * 4)
    IV_binary = bin(int(IV, 16))[2:].zfill(len(IV) * 4)

    #block size = 128
    num_of_blocks = int(len(plaintext_binary)/128)
    P=[]
    for i in range(num_of_blocks):
        start = i*128
        end = i * 128 + 128
        P.append(plaintext_binary[start:end])

    C = []
    C.append(IV)        
    for i in range(num_of_blocks):
        p = int(P[i],2)
        c = int(C[i],16)


        XOR_res = p ^ c
        binary_result = format(XOR_res, f'0{len(P[i])}b')
        hex_str = format(int(binary_result, 2), f'0{(len(binary_result)+3)//4}X')
        encrypted = Enc(hex_str,key)
        C.append(encrypted) 

    # Concatenate the ciphertexts into one hexadecimal string
    concatenated_hex = ''.join(C)    
    
    return concatenated_hex

#unpadding the message using PKCS7 padding scheme
def unpadding(m):
    #the input is the message in hexadecimal
    #find the last byte of the message
    last_byte = m[-2:]

    #convert the last byte to an integer
    last_byte_int = int(last_byte, 16) #the number of added bytes for padding

    #the number of bytes for the plaintext before padding
    n = int(len(m)/2 - last_byte_int)

    m = m[0:2*n]

    return m

def CBC_Dec(ciphertext, key):
    ciphertext_binary = bin(int(ciphertext, 16))[2:].zfill(len(ciphertext) * 4)
    
    #block size = 128
    num_of_blocks = int(len(ciphertext_binary)/128)
    C=[]
    for i in range(num_of_blocks):
        start = i*128
        end = i * 128 + 128
        C.append(ciphertext_binary[start:end])

    P = []      
    for i in range(num_of_blocks - 1):
       
        hex_str = format(int(C[i+1], 2), f'0{(len(C[i+1])+3)//4}X') 
        decrypted = Dec(hex_str,key)

        d = int(decrypted,16) 
        c = int(C[i],2)

        XOR_res = d ^ c
        binary_result = format(XOR_res, f'0{len(C[i])}b')
        hex_result = format(int(binary_result, 2), f'0{(len(binary_result)+3)//4}X') 
        P.append(hex_result)

    concatenated_hex = ''.join(P) 
    #unpadding the plaintext
    P = unpadding(concatenated_hex)   
    
    return P 