from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad


# --------------------------------------------------
# THREE KEYS
# --------------------------------------------------

K1 = bytes.fromhex("1234567890ABCDEF")
K2 = bytes.fromhex("1234567890ABCDEF")
K3 = bytes.fromhex("1234567890ABCDEF")

message = "Classified Text"
plaintext = message.encode()


# --------------------------------------------------
# 3DES ENCRYPTION: E(K1) -> D(K2) -> E(K3)
# --------------------------------------------------

padded = pad(plaintext, DES.block_size)

# E(K1)
cipher1 = DES.new(K1, DES.MODE_ECB)
stage1 = cipher1.encrypt(padded)

# D(K2)
cipher2 = DES.new(K2, DES.MODE_ECB)
stage2 = cipher2.decrypt(stage1)

# E(K3)
cipher3 = DES.new(K3, DES.MODE_ECB)
ciphertext = cipher3.encrypt(stage2)


# --------------------------------------------------
# 3DES DECRYPTION: D(K3) -> E(K2) -> D(K1)
# --------------------------------------------------

# D(K3)
decipher1 = DES.new(K3, DES.MODE_ECB)
stage1_dec = decipher1.decrypt(ciphertext)

# E(K2)
decipher2 = DES.new(K2, DES.MODE_ECB)
stage2_dec = decipher2.encrypt(stage1_dec)

# D(K1)
decipher3 = DES.new(K1, DES.MODE_ECB)
decrypted_padded = decipher3.decrypt(stage2_dec)

decrypted = unpad(
    decrypted_padded,
    DES.block_size
).decode()


# --------------------------------------------------
# OUTPUT
# --------------------------------------------------

print("K1               :", K1.hex().upper())
print("K2               :", K2.hex().upper())
print("K3               :", K3.hex().upper())

print("Original Message  :", message)
print("Ciphertext (HEX)  :", ciphertext.hex().upper())
print("Decrypted Message :", decrypted)
print("Verification      :", message == decrypted)