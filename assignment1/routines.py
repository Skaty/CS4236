from Crypto.Cipher import AES

# 'Fixed' secret key
secret_key = b'\x6B' * 16

def PKCS7_Check_Padding(p):
    '''
    Check if given plaintext conforms to PKCS7 padding.
    '''
    last_char = p[-1]
    if last_char == 0 or last_char >= 17:
        return 0
    ctr = 1 # number of padding characters we have seen

    # Iterate backwards for the last block
    for char_ptr in range(2,17):
        if last_char == ctr:
            return 1

        cur_char = p[-1 * char_ptr]
        if cur_char != last_char:
            return 0 if ctr != last_char else 1
        else:
            ctr += 1

    return 1

def PKCS7_Padder(p, sz):
    '''
    Pads plaintext p according to PKCS7
    '''
    shortfall = sz - (len(p) % sz)
    return p + bytes([shortfall] * shortfall)

def PKCS7_Unpadder(p):
    '''
    Removes padding (if any) from plaintext
    '''
    return_val = p
    if PKCS7_Check_Padding(p) == 1:
        return_val = p[:-1 * p[-1]]

    return return_val

def AES_Padding(p, v):
    '''
    Encrypts plaintext p under AES CBC
    with IV v and a pre-filled secret key.
    '''
    aes_cipher = AES.new(secret_key, AES.MODE_CBC, v)
    return aes_cipher.encrypt(PKCS7_Padder(p, AES.block_size))

def AES_Num_Blocks(c):
    '''
    Determines the number of blocks in the ciphertext
    '''
    return int(len(c) / AES.block_size)

def AES_Valid_Padding(c, v):
    '''
    A padding oracle for AES
    '''
    aes_cipher = AES.new(secret_key, AES.MODE_CBC, v)
    plaintext = aes_cipher.decrypt(c)

    return PKCS7_Check_Padding(plaintext)

if __name__ == '__main__':
    print('Run main.py and not this file!')
