from Cryptodome.Cipher import DES

# 1. Define key and plaintext as hex strings and convert directly to bytes
key = bytes.fromhex("AABB09182736CCDD")
plaintext = bytes.fromhex("123456ABCD132536")

# 2. Initialize DES in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# 3. Encrypt the 8-byte block
ciphertext = cipher.encrypt(plaintext)
print(f"CIPHER: {ciphertext.hex().upper()}")

# 4. Decrypt back to verify
decrypted = cipher.decrypt(ciphertext)
print(f"PLAINTEXT: {decrypted.hex().upper()}")