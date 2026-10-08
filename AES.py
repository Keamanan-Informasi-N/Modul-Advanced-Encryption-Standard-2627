# AES-128
import argparse
import const

def hex_to_bytes(data, name="input"):
    trimmed = "".join(data.split())
    try:
        return bytes.fromhex(trimmed)
    except ValueError:
        raise ValueError(f"{name} is not valid hex") from None
def bytes_to_state(data):
    state = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(data[r + 4*c])
        state.append(row)
    return state

def state_to_bytes(state):
    res = []
    for c in range(4):
        for r in range(4):
            res.append(state[r][c])
    return bytes(res)

def add_round_key(state, words, round):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= words[4 * round + c][r]

    return state

def padding(data):
    pad_len = const.BLOCK_SIZE - (len(data) % const.BLOCK_SIZE)
    pad = bytes([pad_len] * pad_len)
    
    return data + pad

def unpadding(data):
    if not data:
        raise ValueError("Invalid padded data")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > const.BLOCK_SIZE:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")

    return data[:-pad_len]

def split(data):
    blocks = []
    for i in range(0, len(data), const.BLOCK_SIZE):
        blocks.append(data[i:i + const.BLOCK_SIZE])
    
    return blocks

def xor_bytes(a, b):
    res = []
    for i in range(len(a)):
        res.append(a[i]^b[i])
    return bytes(res)

def sub_bytes(state):
    res = []
    for _ in range(4):
        res.append([0] * 4)
        
    for r in range(4):
        for c in range(4):
            res[r][c] = const.S_BOX[state[r][c]]
    
    return res

def shift_rows(state):
    res = []
    
    for _ in range(4):
        res.append([0] * 4)
    
    for r in range(4):
        for c in range(4):
            res[r][c] = state[r][(c+r)%4]
    return res

def mix_columns(state):
    res = []
    for _ in range(4):
        res.append([0]*4)
        
    for c in range(4):
        for r in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(const.MIX_MATRIX[r][k], state[k][c])
            res[r][c] = val
    return res

def gf_mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        
        if high_bit:
            a ^= 0x1B
        
        b>>=1
        
    return res

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    res = []
    for b in word:
        res.append(const.S_BOX[b])
    return res

def key_expansion(key):
    words = []
    for i in range(4):
        words.append(list(key[4 * i:4 * i + 4]))
        
    for i in range(4, 44):
        temp = words[i-1].copy()
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            for j in range(4):
                temp[j] ^= const.RCON[i//4 - 1][j]
                
        word = []
        for j in range(4):
            word.append(words[i-4][j] ^ temp[j])
        
        words.append(word)
            
    return words

def inv_sub_bytes(state):
    res = []
    for i in range(4):
        res.append([0] * 4)
    
    for r in range(4):
        for c in range(4):
            res[r][c] = const.INV_S_BOX[state[r][c]]
    return res

def inv_shift_rows(state):
    res = []
    for _ in range(4):
        res.append([0]*4)
        
    for r in range(4):
        for c in range(4):
            res[r][c] = state[r][(c-r)%4]
    return res

def inv_mix_columns(state):
    res = []
    for _ in range(4):
        res.append([0]*4)
    
    for r in range(4):
        for c in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(const.INV_MIX_MATRIX[r][k], state[k][c])
            res[r][c] = val
    return res

def encrypt(pt, key):
    state = bytes_to_state(pt)
    words = key_expansion(key)
    
    state = cipher(state, words, const.Nr)
    
    return state_to_bytes(state)

def decrypt(ciphertext, key):
    state = bytes_to_state(ciphertext)
    words = key_expansion(key)
    
    state = inv_cipher(state, words, const.Nr)
    
    return state_to_bytes(state)

def encrypt_ecb(pt, key):
    pt = padding(pt)
    cipher = []
    
    for block in split(pt):
        cipher.append(encrypt(block, key))
    
    return b''.join(cipher)

def decrypt_ecb(cipher, key):
    pt = []
    
    for block in split(cipher):
        pt.append(decrypt(block, key))
        
    return unpadding(b''.join(pt))

def encrypt_cbc(pt, key, iv):
    pt = padding(pt)
    cipher = []
    prev = iv
    
    for block in split(pt):
        block = xor_bytes(block, prev)
        encrypted = encrypt(block, key)
        cipher.append(encrypted)
        prev = encrypted
    
    return b''.join(cipher)

def decrypt_cbc(cipher, key, iv):
    pt = []
    prev = iv
    
    for block in split(cipher):
        decrypted = decrypt(block, key)
        pt_block = xor_bytes(decrypted, prev)
        
        pt.append(pt_block)
        prev = block
    
    return unpadding(b''.join(pt))

def cipher(state, words, Nr):
    state = add_round_key(state, words, 0)
    
    for round in range (1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, words, round)
    
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, words, Nr)
    return state

def inv_cipher(state, words, Nr):
    state = add_round_key(state, words, Nr)
    
    for round in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, words, round)
        state = inv_mix_columns(state)
    
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, words, 0)
    return state

def add_common_arguments(parser):
    crypt_parser = parser.add_mutually_exclusive_group(required=True)
    crypt_parser.add_argument('-e', '--encrypt', dest="method", action='store_const', const='enc', help='Encrypt the input')
    crypt_parser.add_argument('-d', '--decrypt', dest="method", action='store_const', const='dec', help='Decrypt the input')
    
    parser.add_argument('key', type=argparse.FileType('r', encoding='utf-8'), help='File contain the key')
    parser.add_argument('input', type=argparse.FileType('r', encoding='utf-8'),  help='File contain the input pt')
    parser.add_argument('output', type=argparse.FileType('w', encoding='utf-8'), help='File to write the output')
    
    return parser

def main():
    parser = argparse.ArgumentParser(description='AES Encryption/Decryption')
    subparsers = parser.add_subparsers(dest='modes', required=True, help='Modes of operation')
    
    ecb_parser = add_common_arguments(subparsers.add_parser('ecb', help='Electronic Codebook'))
    cbc_parser = add_common_arguments(subparsers.add_parser('cbc', help='Cipher Block Chaining'))
    cbc_parser.add_argument('--iv', required=True, type=argparse.FileType('r', encoding='utf-8'), help="File containing the initial vector")
    
    args = parser.parse_args()
    key = hex_to_bytes(args.key.read(), "key")
    
    if len(key) != 16:
        raise ValueError("AES-128 must use 16 bytes of key")
    
    if args.modes == 'ecb':
        if args.method == 'enc':
            data = args.input.read().encode('utf-8')
            res = encrypt_ecb(data, key)
        else:
            data = hex_to_bytes(args.input.read(), "data")
            res = decrypt_ecb(data, key)
    elif args.modes == 'cbc':
        iv = hex_to_bytes(args.iv.read(), "IV")
        if len(iv) != 16:
            raise ValueError("CBC IV must be exactly 16 bytes")
        
        if args.method == 'enc':
            data = args.input.read().encode('utf-8')
            res = encrypt_cbc(data, key, iv)
        else:
            data = hex_to_bytes(args.input.read(), "data")
            res = decrypt_cbc(data, key, iv)
    
    if args.method == 'enc':
        args.output.write(res.hex())
    else:
        args.output.write(res.decode('utf-8'))

if __name__ == '__main__':
    main()