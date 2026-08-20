from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad

# 1. Define the 8-byte key and the plaintext message
key = b"A1B2C3D4"  # Must be exactly 8 bytes for DES
plaintext = b"Confidential Data"

# 2. Initialize the DES cipher in Electronic Codebook (ECB) mode
cipher = DES.new(key, DES.MODE_ECB)

# 3. Apply padding to make the plaintext a multiple of 8 bytes (DES block size)
padded_plaintext = pad(plaintext, DES.block_size)

# 4. Encrypt the padded plaintext
ciphertext = cipher.encrypt(padded_plaintext)
print(f"Encrypted (Hex): {ciphertext.hex()}")

# 5. Decrypt the ciphertext
decrypted_padded = cipher.decrypt(ciphertext)

# 6. Remove padding to recover the original plaintext
original_message = unpad(decrypted_padded, DES.block_size)
print(f"Decrypted Message: {original_message.decode('utf-8')}")
