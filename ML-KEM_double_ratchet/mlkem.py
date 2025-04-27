# Python implementation as per the specifications of the NIST's 
# Federal Information Processing Standards (FIPS) 203,
# Module-Lattice-Based Key-Encapsulation Mechanism Standard
# as available at https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
# By Mr. Akash Angom, Department of Computer Science and Engineering,
# National Institute of Technology Agartala

# -----------------------IMPORTING MODULES--------------------------

import hashlib
import random
import math

# ------------------HELPER AND GENERATOR FUNCTIIONS-----------------

# Random 32 byte array generator
def generate_random_array():
    return [random.randint(0, 255) for _ in range(32)]

# Converting a number into an array containing that single number
def number_to_array(n):
    return [n]

# Converting an array containing one element back to a number
def array_to_number(arr):
    if len(arr) == 1:
        return arr[0]
    else:
        raise ValueError("Array must contain exactly one element")
    
# Bit reversal of seven-bit integer
def reverse_bits_7bit(r):
    if r < 0 or r > 127:
        raise ValueError("Input must be a 7-bit integer (0 to 127).")
    binary_str = f'{r:07b}'
    reversed_binary_str = binary_str[::-1]
    return int(reversed_binary_str, 2)

# Rounding to nearest integer value
def round_nearest(n):
    # Get the fractional part of the number
    fractional_part = n - int(n)    
    # Check if the number is of the form n + 0.5
    if fractional_part == 0.5:
        return int(n) + 1  # Round up to n + 1
    else:
        return round(n) 

# Addition of two arrays    
def custom_add(list1, list2):
    result = [0] * 256
    for i in range(256):
        result[i] = (list1[i] + list2[i])%q  # Element-wise addition
    
    return result 

# Subtraction between two arrays
def custom_sub(list1, list2):
    result = [0] * 256
    for i in range(256):
        result[i] = (list1[i] - list2[i])%q  # Element-wise subtraction
    
    return result 

# Adding nested arrays
def add_nested_arrays(list1, list2):
    result = []
    for i in range(len(list1)):
        inner_result = []  # To store the result of inner list addition
        # Iterate over the inner lists
        for j in range(len(list1[i])):
            inner_result.append((list1[i][j] + list2[i][j])%q)
        
        result.append(inner_result)   
    
    return result     

#-------------------------AUXILIARY ALGORITHMS-----------------------

# 4.1 Cryptographic Functions

# Pseudorandom function (PRF)
def PRF(array1, array2, eta):
    # Concatenate the two arrays
    concatenated_input = bytes(array1) + bytes(array2)
    output_length = 64 * eta
    # Use SHAKE256 with the concatenated input and desired output length
    shake = hashlib.shake_256()
    shake.update(concatenated_input)
    shake_output = shake.digest(output_length)
    output_array = [int(byte) for byte in shake_output]
    
    return output_array

# Hash functions

def H_hash(x):
    input_bytes = bytes(x)
    sha3_hash = hashlib.sha3_256(input_bytes).digest()
    y = list(sha3_hash[:32])
    return y

def J_hash(x):
    concatenated_input = bytes(x)
    output_length = 32
    shake = hashlib.shake_256()
    shake.update(concatenated_input)
    # Generate the output of desired length
    shake_output = shake.digest(output_length)
    # Convert the output to an array of integers (range 0-255)
    y = [int(byte) for byte in shake_output]   
    return y
  
def G_hash(x):
    # Convert input array to bytes
    input_bytes = bytes(x)
    # Compute the SHA3-512 hash of the input
    sha3_hash = hashlib.sha3_512(input_bytes).digest()

    x1 = list(sha3_hash[:32])
    x2 = list(sha3_hash[32:])   
    ghash = x1 + x2
    return ghash

# eXtendable-Output Function (XOF)

# SHAKE128 initialization
def XOF_Init():
    return hashlib.shake_128()

# Absorb input byte array into the XOF context
def XOF_Absorb(ctx, B):
    # Absorb the byte array as is (B is already a byte array)
    return ctx.update(B) 

# Squeeze out length bytes from the XOF context
def XOF_Squeeze(ctx, length: int) -> bytes:
    # Squeeze out 8 * length bytes
    return ctx.digest(8 * length)

# ----------------------General Algorithms ----------------------- 

# 4.2.1 Conversion and Compression Algorithms

# Algorithm 3 (BitsToBytes)
def BitsToBytes(b):
    B = [0] * (len(b) // 8)
    
    for i in range(len(b)):
        B[i // 8] += b[i] * (2 ** (i % 8))
    return B 

# Algorithm 4 (BytesToBits)   
def BytesToBits(B):
    b = [0] * (8 * len(B))   
    C = B.copy()  
      
    for i in range(len(B)):
        for j in range(8):
            b[8 * i + j] = C[i] % 2 
            C[i] = math.floor(C[i]/2)
    return b

# Compression
def compress(ZQ, d):
    Z2D = [0]*(len(ZQ))
    
    for i in range(len(ZQ)):
        Z2D[i] = (round_nearest(((2**d) / q) * ZQ[i])) % (2**d)
    
    return Z2D

# Decompression
def decompress(Z2D, d):
    ZQ = [0] * len(Z2D)
    for i in range(len(Z2D)):
        ZQ[i] = round_nearest(((q/(2**d)) * Z2D[i]))
    
    return ZQ

# Algorithm 5 (ByteEncode)
def ByteEncode(F, d):
    b = [0] * (256 * d)
    
    for i in range(256):
        a = F[i] 
        for j in range(d):
            b[i * d + j] = a % 2
            a = (a - b[i * d + j]) // 2
    B = BitsToBytes(b)   
    return B

# Algorithm 6 (ByteDecode)
def ByteDecode(B, d):
    b = BytesToBits(B)
    F = [0] * 256
    m = 2**d if d < 12 else 3329

    for i in range(256):
        for j in range(d):
            F[i] += (b[i * d + j] * (2 ** j)%m)%m
        F[i] = F[i] % m    
    
    return F

#--------------------------

# 4.2.2 Sampling Algorithms

# Algorithm 7 (SamppleNTT)
def SampleNTT(B):   
    B = bytes(B[:])
    if len(B) != 34:
        raise ValueError("Input byte array must be exactly 34 bytes.")

    ctx = XOF_Init()   
    XOF_Absorb(ctx, B)  
    samples = [0] * 256  
    j = 0

    while j < 256:
        C = XOF_Squeeze(ctx, 3)  # Fresh 3-byte array C from XOF
        d1 = C[0] + 256 * (C[1] % 16)   # 0 <= d1 < 2^12
        d2 = (C[1] // 16) + 16 * C[2]   # 0 <= d2 < 2^12

        if d1 < q:
            samples[j] = d1
            j += 1

        if d2 < q and j < 256:
            samples[j] = d2
            j += 1

        if j < 256:  # Avoid unnecessary squeeze if we've reached the sample limit
            ctx.update(C) 
            
    return list(samples)

# Algorithm 8 (SamplePolyCBD)
def SamplePolyCBD(B, eta):
    b = BytesToBits(B)
    f = [0]*256
    for i in range(256):
        x = sum(b[2*i*eta + j] for j in range(eta)) 
        y = sum(b[2*i*eta + eta + j] for j in range(eta)) 
        f[i] = (x - y) % q 

    return f

# --------------------------------------------------------------------------

# 4.3 The Number-Theoretic Transform

# Algorithm 9 (NTT)
def NTT(f):
    n = len(f) 
    f_hat = f[:] # Copy the input array to avoid modifying it in place
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, n, 2 * length):
            zeta = pow(17, reverse_bits_7bit(i)) % q
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % q
                f_hat[j + length] = (f_hat[j] - t) % q
                f_hat[j] = (f_hat[j] + t) % q
        length //= 2
    return f_hat

# Algorithm 10 (NTT INVERSE)
def NTTinverse(f_hat):
    f = f_hat[:] 
    n = len(f) 
    i = 127 
    
    length = 2
    while length <= 128:
        for start in range(0, n, 2 * length):
            zeta = pow(17, reverse_bits_7bit(i))%q 
            i -= 1  
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q 
                f[j + length] = (zeta * (f[j + length] - t)) % q
        length *= 2 

    f = [(val * 3303) % q for val in f]   
    
    return f

# Algorithm 11 (MultiplyNTTs)
def MultiplyNTTs(f_hat, g_hat):
    h_hat = [0] * 256
    
    for i in range(128):
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        gamma = pow(17, 2*reverse_bits_7bit(i) + 1)

        h_hat[2 * i], h_hat[2 * i + 1] = BaseCaseMultiply(a0, a1, b0, b1, gamma)
    
    return h_hat

# Algorithm 12 (BaseCaseMultiply)
def BaseCaseMultiply(a0, a1, b0, b1, gamma):
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1 

# ----------------------------K-PKE Component Scheme-----------------------------
 

# Algorithm 13 (K-PKE.keyGeneration)
def KeyGen(d):
    hash = G_hash(d+number_to_array(k))
    rho = hash[:32]
    sigma= hash[32:]

    N = 0
    A_hat = [[[] for _ in range(k)] for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = SampleNTT((rho + number_to_array(j) + number_to_array(i)))

    s = [0]*k
    e = [0]*k
    for i in range(k):
        s[i] = (SamplePolyCBD(PRF(sigma, number_to_array(N), eta1), eta1))
        
        N += 1
    for i in range(k):
        e[i] = (SamplePolyCBD(PRF(sigma, number_to_array(N), eta1), eta1))
        
        N += 1

    s_hat = []
    e_hat = []       
    for i in range(k):

        s_hat.append(NTT(s[i]))
        e_hat.append(NTT(e[i]))

    t_hat = []
    Abar_sbar = []    
    
    for i in range(k):
        sum = [0]*256    
        for j in range(k):
                product = MultiplyNTTs(A_hat[i][j],s_hat[j])
                
                sum = custom_add(sum, product)
                   
        Abar_sbar.append(sum)                           
    
    t_hat = add_nested_arrays(Abar_sbar, e_hat)

    ekPKE_parts = []
    for i in range(k): 
        ekPKE_parts += (ByteEncode(t_hat[i], 12))
    
    ekPKE = ekPKE_parts[:] + rho
     
    dkPKE_parts = []
    for i in range(k): 
        dkPKE_parts += (ByteEncode(s_hat[i], 12))
    
    dkPKE = dkPKE_parts[:]

    return ekPKE, dkPKE

# Algorithm 14 (K-PKE Encryption)
def Encrypt(ek_pke, m, r):   
    N = 0
    t_hatparts = []
    
    for j in range(k):
        inner_list = ek_pke[384*j:384*(j+1)]
        t_hatparts.append(ByteDecode(inner_list, 12))         
    
    t_hat = t_hatparts[:]

    rho = ek_pke[384*k:384*k+32]

    A_hat = [[[] for _ in range(k)] for _ in range(k)]
    
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = SampleNTT((rho + number_to_array(j) + number_to_array(i)))

    y = [0]*k
    e1 = [0]*k
    e2 = []
    
    for i in range(k):
        y[i] = SamplePolyCBD(PRF(r, number_to_array(N), eta1), eta1)
        N +=1
        
    for i in range(k):
        e1[i] = SamplePolyCBD(PRF(r, number_to_array(N), eta2), eta2)
        N +=1                
    
    e2 = SamplePolyCBD(PRF(r, number_to_array(N), eta2), eta2)

    y_hat = []
    for i in range(k):
        y_hat.append(NTT(y[i]))

    u = []
    A_hatT = A_hat[:]
    At_y = []
                
    for i in range(k):
        sum1 = [0]*256    
        for j in range(k):
            product = NTTinverse(MultiplyNTTs(A_hatT[j][i],y_hat[j]))
                
            sum1 = custom_add(sum1, product)
                   
        At_y.append(sum1)
                                
    u = add_nested_arrays(At_y, e1)
   
    myu = decompress(ByteDecode(m, 1), 1)
    
    v = []
    tT_y = []
    t_hatT = t_hat[:]

    sum2 = [0]*256  
    for j in range(k):
        product = (MultiplyNTTs(t_hatT[j], y_hat[j]))
        sum2 = custom_add(sum2, product)
    tT_y = sum2[:] 

    v = custom_add(custom_add(NTTinverse(tT_y), e2), myu)
    c1 = []
  
    for i in range(k):
        c1 += (ByteEncode(compress(u[i], du), du))       
  
    c2 = ByteEncode(compress(v, dv), dv)
    c = c1 + c2

    return c

# Algorithm 15 (K-PKE Decryption)
def Decrypt(dk_pke, c):
    c1 = c[:32*du*k]
    c2 = c[32*du*k : 32*(du*k+dv)]

    c1_12 = []
    
    for i in range(k):
        # Each inner list contains 32*du elements sliced from the input list
        start_index = i * 32 * du
        end_index = start_index + 32 * du
        inner_list = c[start_index:end_index]
        c1_12.append(inner_list) 

    u_bar = []
    v_bar = []
       
    for i in range(k):
        u_bar.append(decompress(ByteDecode(c1_12[i], du), du))

    v_bar = decompress(ByteDecode(c2, dv), dv)

    s_hat = []
    for i in range(k):
        start_index = i * 384
        end_index = start_index + 384
        inner_list = dk_pke[start_index:end_index]
        s_hat.append(ByteDecode(inner_list, 12)) 

    w = []
    u_bar_hat = []
    for i in range(k):
        u_bar_hat.append(NTT(u_bar[i])) 
 
    st_ubarhat = [0]*256   
    
    for j in range(k):
        product = (MultiplyNTTs(s_hat[j], u_bar_hat[j]))
        st_ubarhat = custom_add(st_ubarhat, product)

    w  = custom_sub(v_bar, NTTinverse(st_ubarhat)) 
          
    m = ByteEncode(compress(w, 1), 1)

    return m

# -------------------------MAIN INTERNAL ALGORITHMS-------------------------

# Algorithm 16 (MLKEM.Internal Key Generation)
def KeyGen_internal(d, z):
    
    ek_pke, dk_pke = KeyGen(d)
    ek = ek_pke[:]
    dk = (dk_pke + ek + H_hash(ek) + z)
  
    return ek, dk

# Algorithm 17 (MLKEM.Internal Encapsulation)   
def Encaps_internal(ek, m):   
    hashkc = G_hash(m + H_hash(ek))
    K = hashkc[:32]
    r = hashkc[32:]   
    c = Encrypt(ek, m, r)
    
    return K, c

# Algorithm 18 (MLKEM.Internal Decapsulation)
def Decaps_internal(dk, c):
    dk_pke = dk[:384*k]
    ek_pke = dk[384*k : 768*k + 32]

    h = dk[768*k + 32 : 768*k + 64]
    z = dk[768*k + 64 : 768*k + 96]
    m_bar = Decrypt(dk_pke, c)
    hashG_krbar = G_hash(m_bar + h)
    #hashG_krbar = G_hash(m_bar + list(h))

    K_bar = hashG_krbar[:32]
    r_bar = hashG_krbar[32:]
    
    KKBAR = J_hash(z + c)
    
    #KKBAR = J_hash(bytes(z) + bytes(c))


    c_bar = Encrypt(ek_pke, m_bar, r_bar)
    if(c != c_bar):
        K_bar = KKBAR
    
    return K_bar

# ---------------------MLKEM Key-Encapsulation Mechanisms--------------------

# Algorithm 19 (MLKEM KEYGEN)
def ML_KEM_KEYGEN():
    
    d = generate_random_array()
    z = generate_random_array()
    
    if(d==[] or z==[]):
        return print("ERROR: KEYGEN Failed! (Random Bit Generation)")
    
    ek, dk = KeyGen_internal(d, z)
    return ek, dk

# Algorithm 20 (MLKEM KEYENCAP)   
def ML_KEM_ENCAPS(ek):
    
    m = generate_random_array()
    if (m==[]):
        return print("ERROR: ENCAPS Failed! (Random Bit Generation)")
    
    K, c = Encaps_internal(ek, m)
    return K, c

# Algorithm 21 (MLKEM KEYDECAP)        
def ML_KEM_DECAPS(dk, c):
    K_bar = Decaps_internal(dk, c)
    return K_bar 

#------------------PARAMETER SETS AND CALLING FUNCTIONS-------------------- 
   

# Common parameters for ML-KEM-512
n = 256
q = 3329

k = 3
eta1 = 2
eta2 = 2
du = 10
dv = 4

# print("\nChoose the parameter sets...")
# print("1: ML-KEM-512")
# print("2: ML-KEM-768")
# print("3: ML-KEM-1024")

# user_input = int(input("Enter your choice as numbers (1, 2 or 3): "))
# if user_input == 1:
#     k = 2
#     eta1 = 3
#     eta2 = 2
#     du = 10
#     dv = 4
    
#     print("")
#     print("")
#     print("Sizes (in bytes) of keys and ciphertexts of ML-KEM-512")
#     print("")

# elif user_input == 2:
#     k = 3
#     eta1 = 2
#     eta2 = 2
#     du = 10
#     dv = 4
    
#     print("")
#     print("")
#     print("Sizes (in bytes) of keys and ciphertexts of ML-KEM-768")
#     print("")

# elif user_input == 3:
#     k = 4
#     eta1 = 2
#     eta2 = 2
#     du = 11
#     dv = 5
    
#     print("")
#     print("")
#     print("Sizes (in bytes) of keys and ciphertexts of ML-KEM-1024")
#     print("")    

# else: exit()        

# # The ML-KEM Key-Encapsulation Mechanism
# ek, dk = ML_KEM_KEYGEN()
# K, c = ML_KEM_ENCAPS(ek)
# K_prime = ML_KEM_DECAPS(dk, c)

# # Printing the sizes

# print("Length of encapsulation key: ", len(ek))
# print("Length of decapsulation key: ", len(dk))
# print("Length of ciphertext: ", len(c))
# print("Length of shared secret key: ", len(K or K_prime))
# print("")
# print("")

# # Printing the values in hexadecimal representation
# print("Printing the values in hexadecimal representation...")
# print("")
# Encapsulation_key = ''.join(format(i, '02x') for i in ek)
# print("Encapsulation key: ", Encapsulation_key)
# Ciphertext = ''.join(format(i, '02x') for i in c)
# print("Ciphertext: ", Ciphertext)
# Decapsulation_key = ''.join(format(i, '02x') for i in dk)
# print("Decapsulation key: ", Decapsulation_key)
# Bob_shared_key = ''.join(format(i, '02x') for i in K)
# print("Bob shared key: ", Bob_shared_key)
# Alice_shared_key = ''.join(format(i, '02x') for i in K_prime)
# print("Alice shared key: ", Alice_shared_key) 


# ------------------------------------------------------------------
# -------------------------------- E N D ---------------------------
# ------------------------------------------------------------------




