from Cryptodome.Cipher import DES, AES
from Cryptodome.Util.Padding import pad, unpad
import time


# --------------------------------------------------
# MESSAGE AND KEYS
# --------------------------------------------------

message = "Performance Testing of Encryption Algorithms"
plaintext = message.encode("utf-8")

# DES key = 8 bytes
des_key = b"12345678"

# AES-256 key = 32 bytes
aes_key = b"0123456789ABCDEF0123456789ABCDEF"


# Number of repetitions
ITERATIONS = 100000


# ==================================================
# DES
# ==================================================

# Pad once so padding time is NOT included
des_plaintext = pad(plaintext, DES.block_size)


# ---------------- DES ENCRYPTION ----------------

start = time.perf_counter()

for _ in range(ITERATIONS):
    cipher = DES.new(des_key, DES.MODE_ECB)
    des_ciphertext = cipher.encrypt(des_plaintext)

end = time.perf_counter()

des_encrypt_time = (end - start) / ITERATIONS


# ---------------- DES DECRYPTION ----------------

start = time.perf_counter()

for _ in range(ITERATIONS):
    decipher = DES.new(des_key, DES.MODE_ECB)
    des_decrypted = decipher.decrypt(des_ciphertext)

end = time.perf_counter()

des_decrypt_time = (end - start) / ITERATIONS


# ==================================================
# AES-256
# ==================================================

# Pad once so padding time is NOT included
aes_plaintext = pad(plaintext, AES.block_size)


# ---------------- AES ENCRYPTION ----------------

start = time.perf_counter()

for _ in range(ITERATIONS):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    aes_ciphertext = cipher.encrypt(aes_plaintext)

end = time.perf_counter()

aes_encrypt_time = (end - start) / ITERATIONS


# ---------------- AES DECRYPTION ----------------

start = time.perf_counter()

for _ in range(ITERATIONS):
    decipher = AES.new(aes_key, AES.MODE_ECB)
    aes_decrypted = decipher.decrypt(aes_ciphertext)

end = time.perf_counter()

aes_decrypt_time = (end - start) / ITERATIONS


# ==================================================
# VERIFY DECRYPTION
# ==================================================

des_result = unpad(des_decrypted, DES.block_size).decode()
aes_result = unpad(aes_decrypted, AES.block_size).decode()


# ==================================================
# RESULTS
# ==================================================

print("Message:")
print(message)

print("\nDES Ciphertext:")
print(des_ciphertext.hex().upper())

print("\nAES-256 Ciphertext:")
print(aes_ciphertext.hex().upper())

print("\nDecrypted using DES:")
print(des_result)

print("\nDecrypted using AES-256:")
print(aes_result)

print("\nVerification:")
print("DES :", des_result == message)
print("AES :", aes_result == message)


print("\n" + "=" * 50)
print("PERFORMANCE RESULTS")
print("=" * 50)

print(f"DES Encryption : {des_encrypt_time * 1_000_000:.4f} µs")
print(f"DES Decryption : {des_decrypt_time * 1_000_000:.4f} µs")

print(f"AES-256 Encryption : {aes_encrypt_time * 1_000_000:.4f} µs")
print(f"AES-256 Decryption : {aes_decrypt_time * 1_000_000:.4f} µs")


# ==================================================
# COMPARISON
# ==================================================

print("\n" + "=" * 50)
print("COMPARISON")
print("=" * 50)

print(
    f"DES encryption is "
    f"{des_encrypt_time / aes_encrypt_time:.2f}x "
    f"the AES-256 encryption time."
)

print(
    f"DES decryption is "
    f"{des_decrypt_time / aes_decrypt_time:.2f}x "
    f"the AES-256 decryption time."
)