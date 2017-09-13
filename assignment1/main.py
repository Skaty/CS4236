from Crypto.Cipher import AES

import routines
import sys

def print_hex(b_str):
    '''
    Helper function that prints a byte string in hexadecimal representation.
    '''
    print(' '.join('{:02X}'.format(ch) for ch in b_str))

def pad_blocks_behind(ciphertext, solved_text, idx, blk_sz, padding_val):
    '''
    XORs the cracked bytes in the current block
    '''
    for solved_pos in range(-1 * (blk_sz + 1), idx, -1):
        ciphertext[solved_pos] = ciphertext[solved_pos] ^ solved_text[solved_pos + blk_sz] ^ padding_val

def extract_iv_ciphertext_from_combination(combination, blk_sz):
    '''
    Returns an (iv, ciphertext) tuple from a iv+ciphertext bytestring
    '''
    return (bytes(combination[:blk_sz]), bytes(combination[blk_sz:]))

def crack_byte(ciphertext, iv, solved_text, blk_sz, pos):
    '''
    Cracks a given byte position in the ciphertext block
    - pos denotes the byte number, starting from the right of the last block.
    '''
    padding_val = pos
    idx = -1 * (pos + blk_sz)
    iv_cipher = bytearray(iv + ciphertext)
    cipher_byte = iv_cipher[idx]

    pad_blocks_behind(iv_cipher, solved_text, idx, blk_sz, padding_val)

    for byte_val in range(0, 256):
        iv_cipher[idx] = cipher_byte ^ byte_val ^ padding_val
        new_iv, final_ciphertext = extract_iv_ciphertext_from_combination(iv_cipher, blk_sz)
        without_filter = routines.AES_Valid_Padding(final_ciphertext, new_iv)

        # This part ensures that the uncracked bytes do not
        # unintentionally form longer padding with the byte to be cracked
        if pos % blk_sz != 0:
            iv_cipher[idx - 1] = iv_cipher[idx - 1] ^ 0xFF

        new_iv, final_ciphertext = extract_iv_ciphertext_from_combination(iv_cipher, blk_sz)
        with_filter = routines.AES_Valid_Padding(final_ciphertext, new_iv)

        if with_filter == 1 and without_filter == 1:
            return byte_val

    return 0

def AES_Oracle_Attack(iv, ciphertext):
    '''
    Performs a padding oracle attack given an IV and ciphertext
    Returns the cracked string as a byte string.
    '''
    num_blocks = routines.AES_Num_Blocks(ciphertext)
    cracked_text = b''
    current_cracked_block = b''
    blk_sz = AES.block_size

    for blk_num in range(0, num_blocks): # zero-indexed block number
        truncated_ciphertext = ciphertext[:blk_sz*(num_blocks - blk_num)]
        cracked_block = b''
        for byte_num in range(0, blk_sz):
            cracked_val = crack_byte(truncated_ciphertext, iv, cracked_block, blk_sz, byte_num + 1)
            cracked_block = bytes([cracked_val]) + cracked_block

        cracked_text = cracked_block + cracked_text

    return cracked_text


# Faulty plaintext: anoE+[JD|D27M@$58q(Q|Y;S<fT/Xg= !&L2MxfAg?e=x;MOAO\"3o`_>7q}xvh1K8;m<N2VX9J{FF`Sa9TUp4fg*;?.Br{7\"3m4=vkN(YQ9i7NCK8rCPE\"[jeZ7<a,3P as5BxICg<R\"],#`mJaZ<

if __name__ == '__main__':
    '''
    Performs AES Oracle attack through STDIN
    '''
    plaintext = ""
    for ln in sys.stdin.readlines():
        plaintext += ln

    # plaintext = sys.stdin.read() # read in a string of alphabets p with length n where 0 < n < 300.
    plaintext_bytes = plaintext.encode('ascii')
    iv =  b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00' # set v to be a 16-byte string with hexadecimal values

    ciphertext = routines.AES_Padding(plaintext_bytes, iv)

    print_hex(ciphertext)

    cracked_text = AES_Oracle_Attack(iv, ciphertext)

    print(routines.PKCS7_Unpadder(cracked_text).decode('ascii'))
