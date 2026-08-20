from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


# AES-128 key
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)

# Original message
message = "Sensitive Information"

# Convert message to bytes
plaintext = message.encode("utf-8")


# ---------------- ENCRYPTION ----------------

# Add PKCS#7 padding
padded_plaintext = pad(
    plaintext,
    AES.block_size
)

# AES-128 using ECB mode
cipher = AES.new(
    key,
    AES.MODE_ECB
)

ciphertext = cipher.encrypt(
    padded_plaintext
)


# ---------------- DECRYPTION ----------------

decipher = AES.new(
    key,
    AES.MODE_ECB
)

decrypted_padded = decipher.decrypt(
    ciphertext
)

# Remove padding
decrypted = unpad(
    decrypted_padded,
    AES.block_size
)

decrypted_message = decrypted.decode("utf-8")


# ---------------- OUTPUT ----------------

print("Original Message :", message)
print("Key              :", key.hex().upper())
print("Ciphertext (HEX) :", ciphertext.hex().upper())
print("Decrypted Message:", decrypted_message)
print("Verification     :", message == decrypted_message)