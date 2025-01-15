from constants import P_array, S_box

class Blowfish:
    
    P = P_array
    S = S_box

    def __init__(self, key):
        self.P = self.P[:]
        self.S = [s[:] for s in self.S]
        self.key_expansion(key)
    
    def key_expansion(self, key):
        key_len = len(key)
        for i in range(18):
            key_part = int.from_bytes(key[i % key_len:i % key_len + 4], 'big')
            self.P[i] ^= key_part
        block = 0
        for i in range(0, 18, 2):
            block = self.encrypt_block(block)
            self.P[i], self.P[i + 1] = block >> 32, block & 0xFFFFFFFF
        
        for i in range(4):
            for j in range(0, 256, 2):
                block = self.encrypt_block(block)
                self.S[i][j], self.S[i][j + 1] = block >> 32, block & 0xFFFFFFFF
    
    def encrypt_block(self, block):
        left = block >> 32
        right = block & 0xFFFFFFFF
        
        for i in range(16):
            left ^= self.P[i]
            right ^= self.F(left)
            left, right = right, left
        
        left, right = right, left
        right ^= self.P[16]
        left ^= self.P[17]
        return (left << 32) | right
    
    def decrypt_block(self, block):
        left = block >> 32
        right = block & 0xFFFFFFFF
        
        for i in range(17, 1, -1):
            left ^= self.P[i]
            right ^= self.F(left)
            left, right = right, left
        
        left, right = right, left
        right ^= self.P[1]
        left ^= self.P[0]
        return (left << 32) | right

    def F(self, x):
        h = self.S[0][x >> 24] + self.S[1][(x >> 16) & 0xFF]
        h ^= self.S[2][(x >> 8) & 0xFF]
        h += self.S[3][x & 0xFF]
        return h & 0xFFFFFFFF

    @staticmethod
    def pad(data, block_size):
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([padding_len] * padding_len)

    @staticmethod
    def unpad(data):
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt_cbc(self, plaintext, iv):
        plaintext = self.pad(plaintext, 8)
        blocks = [plaintext[i:i + 8] for i in range(0, len(plaintext), 8)]
        ciphertext = b""
        prev_block = int.from_bytes(iv, 'big')

        for block in blocks:
            block_int = int.from_bytes(block, 'big') ^ prev_block
            encrypted_block = self.encrypt_block(block_int)
            ciphertext += encrypted_block.to_bytes(8, 'big')
            prev_block = encrypted_block

        return ciphertext

    def decrypt_cbc(self, ciphertext, iv):
        blocks = [ciphertext[i:i + 8] for i in range(0, len(ciphertext), 8)]
        plaintext = b""
        prev_block = int.from_bytes(iv, 'big')

        for block in blocks:
            block_int = int.from_bytes(block, 'big')
            decrypted_block = self.decrypt_block(block_int) ^ prev_block
            plaintext += decrypted_block.to_bytes(8, 'big')
            prev_block = block_int

        return self.unpad(plaintext)
