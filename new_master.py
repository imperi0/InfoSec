import os
import json
import random
import hashlib
from datetime import datetime

# --- Cryptographic Libraries (PyCryptodome & Cryptography) ---
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


# ==============================================================================
# SECTION 1: ALL SYMMETRIC CIPHERS (CLASSICAL & MODERN) [Labs 1 & 2]
# ==============================================================================

# --- Classical: Additive / Caesar Cipher ---
def caesar_encrypt(plaintext, shift):
    res = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            res += chr((ord(char) - base + shift) % 26 + base)
        else:
            res += char
    return res


def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)


# --- Classical: Multiplicative Cipher ---
def multiplicative_encrypt(plaintext, key):
    res = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            res += chr(((ord(char) - base) * key) % 26 + base)
        else:
            res += char
    return res


def multiplicative_decrypt(ciphertext, key):
    key_inv = pow(key, -1, 26)  # Requires coprime key: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
    return multiplicative_encrypt(ciphertext, key_inv)


# --- Classical: Affine Cipher ---
def affine_encrypt(plaintext, k1, k2):
    res = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            res += chr((((ord(char) - base) * k1) + k2) % 26 + base)
        else:
            res += char
    return res


def affine_decrypt(ciphertext, k1, k2):
    k1_inv = pow(k1, -1, 26)
    res = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            res += chr((((ord(char) - base - k2) * k1_inv) % 26) + base)
        else:
            res += char
    return res


# --- Classical: Vigenère Cipher ---
def vigenere_encrypt(plaintext, key):
    res = []
    key = key.upper()
    key_idx = 0
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            res.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            res.append(char)
    return "".join(res)


def vigenere_decrypt(ciphertext, key):
    res = []
    key = key.upper()
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            res.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            res.append(char)
    return "".join(res)


# --- Modern: DES (ECB & CBC Modes) ---
def des_encrypt(plaintext, key_8bytes):
    cipher = DES.new(key_8bytes, DES.MODE_ECB)
    padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(padded_data).hex()


def des_decrypt(ciphertext_hex, key_8bytes):
    cipher = DES.new(key_8bytes, DES.MODE_ECB)
    decrypted_padded = cipher.decrypt(bytes.fromhex(ciphertext_hex))
    return unpad(decrypted_padded, DES.block_size).decode('utf-8')


def des_cbc_encrypt(plaintext, key_8bytes):
    cipher = DES.new(key_8bytes, DES.MODE_CBC)
    padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
    return f"{cipher.iv.hex()}:{cipher.encrypt(padded_data).hex()}"


def des_cbc_decrypt(packed_ciphertext, key_8bytes):
    iv_hex, ct_hex = packed_ciphertext.split(":")
    cipher = DES.new(key_8bytes, DES.MODE_CBC, iv=bytes.fromhex(iv_hex))
    return unpad(cipher.decrypt(bytes.fromhex(ct_hex)), DES.block_size).decode('utf-8')


# --- Modern: Triple DES (3DES ECB & CBC) ---
def des3_ecb_encrypt(plaintext, key_16or24bytes):
    key = DES3.adjust_key_parity(key_16or24bytes)
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), DES3.block_size)
    return cipher.encrypt(padded).hex()


def des3_ecb_decrypt(ciphertext_hex, key_16or24bytes):
    key = DES3.adjust_key_parity(key_16or24bytes)
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(bytes.fromhex(ciphertext_hex))
    return unpad(decrypted, DES3.block_size).decode('utf-8')


def des3_cbc_encrypt(plaintext, key_16or24bytes):
    key = DES3.adjust_key_parity(key_16or24bytes)
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded = pad(plaintext.encode('utf-8'), DES3.block_size)
    return f"{cipher.iv.hex()}:{cipher.encrypt(padded).hex()}"


def des3_cbc_decrypt(packed_ciphertext, key_16or24bytes):
    iv_hex, ct_hex = packed_ciphertext.split(":")
    key = DES3.adjust_key_parity(key_16or24bytes)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=bytes.fromhex(iv_hex))
    return unpad(cipher.decrypt(bytes.fromhex(ct_hex)), DES3.block_size).decode('utf-8')


# --- Modern: AES (ECB & CBC Modes for 128, 192, 256 bits) ---
def aes_encrypt(plaintext, key_16bytes):
    cipher = AES.new(key_16bytes, AES.MODE_CBC)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return f"{cipher.iv.hex()}:{ciphertext.hex()}"


def aes_decrypt(packed_ciphertext, key_16bytes):
    iv_hex, ciphertext_hex = packed_ciphertext.split(":")
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(key_16bytes, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')


def aes_ecb_encrypt(plaintext, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded).hex()


def aes_ecb_decrypt(ciphertext_hex, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted = cipher.decrypt(bytes.fromhex(ciphertext_hex))
    return unpad(decrypted, AES.block_size).decode('utf-8')


# ==============================================================================
# SECTION 2: ALL ASYMMETRIC CIPHERS, KEY EXCHANGE & SIGNATURES [Labs 3, 4 & 6]
# ==============================================================================

# --- RSA Encryption & Decryption ---
def rsa_encrypt(plaintext, rsa_public_key):
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(plaintext.encode('utf-8')).hex()


def rsa_decrypt(ciphertext_hex, rsa_private_key):
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(bytes.fromhex(ciphertext_hex)).decode('utf-8')


# --- RSA Signatures ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


def rsa_sign(data_to_sign, rsa_private_key):
    h = SHA256.new(data_to_sign.encode('utf-8'))
    signature = pkcs1_15.new(rsa_private_key).sign(h)
    return signature.hex()


def rsa_verify(data_to_verify, signature_hex, rsa_public_key):
    h = SHA256.new(data_to_verify.encode('utf-8'))
    try:
        pkcs1_15.new(rsa_public_key).verify(h, bytes.fromhex(signature_hex))
        return True
    except (ValueError, TypeError):
        return False


# --- ECC Signatures (PyCryptodome Persistent DSS Implementation) ---
def generate_ecc_keys():
    private_key = ECC.generate(curve='P-256')
    return private_key, private_key.public_key()


def ecc_sign(data_to_sign, ecc_private_key):
    h = SHA256.new(data_to_sign.encode('utf-8'))
    signer = DSS.new(ecc_private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature.hex()


def ecc_verify(data_to_verify, signature_hex, ecc_public_key):
    h = SHA256.new(data_to_verify.encode('utf-8'))
    verifier = DSS.new(ecc_public_key, 'fips-186-3')
    try:
        verifier.verify(h, bytes.fromhex(signature_hex))
        return True
    except (ValueError, TypeError):
        return False


# --- ElGamal Encryption & Digital Signatures ---
def elgamal_generate_keys(p=467, g=2):
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x


def elgamal_encrypt(plaintext_int, public_key):
    p, g, y = public_key
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (plaintext_int * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(c1, c2, private_key, p):
    s = pow(c1, private_key, p)
    s_inv = pow(s, p - 2, p)
    return (c2 * s_inv) % p


def elgamal_sign(data_to_sign, public_key, private_key):
    p, g, y = public_key
    x = private_key
    h_val = int(hashlib.sha256(data_to_sign.encode('utf-8')).hexdigest(), 16) % (p - 1)

    while True:
        k = random.randint(1, p - 2)
        if pow(k, -1, p - 1) is not None:
            break

    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h_val - x * r)) % (p - 1)
    return r, s


def elgamal_verify(data_to_verify, signature, public_key):
    p, g, y = public_key
    r, s = signature
    if not (0 < r < p):
        return False
    h_val = int(hashlib.sha256(data_to_verify.encode('utf-8')).hexdigest(), 16) % (p - 1)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h_val, p)
    return v1 == v2


# --- Rabin Cryptosystem (Encryption & Decryption) ---
def rabin_generate_keys(p=7, q=11):
    n = p * q
    return n, (p, q)


def rabin_encrypt(plaintext_int, n):
    return pow(plaintext_int, 2, n)


def rabin_decrypt(ciphertext_int, private_key):
    p, q = private_key
    n = p * q
    r = pow(ciphertext_int, (p + 1) // 4, p)
    s = pow(ciphertext_int, (q + 1) // 4, q)

    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    _, a, b = egcd(p, q)
    x = (a * p * s + b * q * r) % n
    y = (a * p * s - b * q * r) % n

    roots = [x, n - x, y, n - y]
    return list(set(roots))


# --- Diffie-Hellman Key Exchange ---
def dh_generate_keys(p=23, g=5):
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return public_key, private_key


def dh_compute_shared_secret(their_public_key, my_private_key, p=23):
    return pow(their_public_key, my_private_key, p)


# ==============================================================================
# SECTION 3: ALL HASH FUNCTIONS [Lab 5]
# ==============================================================================

def get_sha256_hash(plaintext):
    """Standard SHA-256 Hash"""
    return hashlib.sha256(plaintext.encode('utf-8')).hexdigest()


def get_md5_hash(plaintext):
    """MD5 Hash"""
    return hashlib.md5(plaintext.encode('utf-8')).hexdigest()


def get_custom_hash(plaintext):
    """Lab 5 Custom Hash (Multiplier 33, Hash 5381, 32-bit mask)"""
    h = 5381
    for char in plaintext:
        h = ((h * 33) + ord(char)) & 0xFFFFFFFF
    return hex(h)[2:]


# ==============================================================================
# SECTION 4: ROLE-BASED ACCESS CONTROL (RBAC) & FILE I/O LAYER [Labs 4 & QP Format]
# ==============================================================================

DB_FILE = "database.json"


def save_to_db(record_dict):
    records = []
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            try:
                records = json.load(f)
            except json.JSONDecodeError:
                records = []
    records.append(record_dict)
    with open(DB_FILE, "w") as f:
        json.dump(records, f, indent=4)


def load_from_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


# ==============================================================================
# SECTION 5: PERSISTENT KEYS & PASSWORD-BASED ROLE AUTHENTICATION
# ==============================================================================

RSA_PRIVATE_FILE = "rsa_private.pem"
RSA_PUBLIC_FILE = "rsa_public.pem"

ECC_PRIVATE_FILE = "ecc_private.pem"
ECC_PUBLIC_FILE = "ecc_public.pem"

PASSWORDS = {
    "student": "student123",
    "faculty": "faculty123",
    "hod": "hod123"
}


def load_or_generate_rsa_keys():
    """Load existing RSA keys or generate and save them on first run."""
    if os.path.exists(RSA_PRIVATE_FILE) and os.path.exists(RSA_PUBLIC_FILE):
        with open(RSA_PRIVATE_FILE, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(RSA_PUBLIC_FILE, "rb") as f:
            public_key = RSA.import_key(f.read())
        return private_key, public_key

    private_key, public_key = generate_rsa_keys()

    with open(RSA_PRIVATE_FILE, "wb") as f:
        f.write(private_key.export_key())

    with open(RSA_PUBLIC_FILE, "wb") as f:
        f.write(public_key.export_key())

    return private_key, public_key


def load_or_generate_ecc_keys():
    """Load existing ECC keys or generate and save them on first run."""
    if os.path.exists(ECC_PRIVATE_FILE) and os.path.exists(ECC_PUBLIC_FILE):
        with open(ECC_PRIVATE_FILE, "rt") as f:
            private_key = ECC.import_key(f.read())
        with open(ECC_PUBLIC_FILE, "rt") as f:
            public_key = ECC.import_key(f.read())
        return private_key, public_key

    private_key, public_key = generate_ecc_keys()

    with open(ECC_PRIVATE_FILE, "wt") as f:
        f.write(private_key.export_key(format='PEM'))

    with open(ECC_PUBLIC_FILE, "wt") as f:
        f.write(public_key.export_key(format='PEM'))

    return private_key, public_key


def authenticate(role):
    """Simple password authentication for the three system roles."""
    password = input(f"Enter {role.capitalize()} Password: ")

    if password == PASSWORDS[role]:
        print(">> Authentication successful.")
        return True

    print(">> Access Denied. Incorrect password.")
    return False


# ==============================================================================
# MAIN EDUSecure SYSTEM
# ==============================================================================

def main_system():
    # Persistent RSA keypair
    rsa_priv, rsa_pub = load_or_generate_rsa_keys()

    # Persistent ECC keypair
    ecc_priv, ecc_pub = load_or_generate_ecc_keys()

    # ElGamal keypair generated for global usage
    elgamal_pub, elgamal_priv = elgamal_generate_keys(p=467, g=2)

    while True:
        print("\n=== EDUSecure ROLE-BASED ACCESS CONTROL ===")
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        choice = input("Select Role (1-4): ")

        # ==============================================================
        # STUDENT
        # ==============================================================
        if choice == '1':
            if not authenticate("student"):
                continue

            while True:
                print("\n--- [ROLE 1: STUDENT] ---")
                print("1. Upload Academic Record")
                print("2. View My Previous Records")
                print("3. Back")

                student_choice = input("Enter choice (1-3): ")

                if student_choice == '1':
                    student_id = input("Enter Student ID: ")
                    filename = input(
                        "Enter File/Record Name (Press Enter for default): "
                    ) or "record_01.txt"
                    plaintext = input("Enter record content: ")

                    # ------------------------------------------------------------------
                    # DYNAMIC KEY INPUTS (KEEP THESE FOR CHANGED QUESTIONS)
                    # ------------------------------------------------------------------

                    # 1. DES Key Input (8 bytes)
                    raw_des = input(
                        "Enter 8-byte DES key (Press Enter for default '8ByteKey'): "
                    ) or "8ByteKey"
                    des_key = raw_des[:8].ljust(8, '0').encode('utf-8')

                    # 2. 3DES Key Input (16 or 24 bytes)
                    # raw_3des = input("Enter 16 or 24-byte 3DES key: ") or "16ByteKey1234567"
                    # des3_key = raw_3des[:16].ljust(16, '0').encode('utf-8')

                    # 3. AES-128 Key Input (16 bytes)
                    # raw_aes128 = input("Enter 16-byte AES key: ") or "16ByteKey1234567"
                    # aes128_key = raw_aes128[:16].ljust(16, '0').encode('utf-8')

                    # 4. AES-192 Key Input (24 bytes)
                    # raw_aes192 = input("Enter 24-byte AES key: ") or "24ByteKey123456789012345"
                    # aes192_key = raw_aes192[:24].ljust(24, '0').encode('utf-8')

                    # 5. AES-256 Key Input (32 bytes)
                    # raw_aes256 = input("Enter 32-byte AES key: ") or "32ByteKey1234567890123456789012"
                    # aes256_key = raw_aes256[:32].ljust(32, '0').encode('utf-8')

                    # 6. Caesar / Additive Shift Input
                    # additive_key = int(input("Enter Additive Shift Key (Press Enter for 3): ") or "3")

                    # 7. Multiplicative Key Input (Must be coprime with 26)
                    # multiplicative_key = int(input("Enter Coprime Multiplicative Key (Press Enter for 7): ") or "7")

                    # 8. Affine Keys Input
                    # affine_k1 = int(input("Enter k1 (coprime with 26, default 7): ") or "7")
                    # affine_k2 = int(input("Enter k2 (shift, default 2): ") or "2")

                    # 9. Vigenère Key Input
                    # vigenere_key = input("Enter Vigenère Keyword (Press Enter for 'KEYWORD'): ") or "KEYWORD"

                    # ------------------------------------------------------------------
                    # ENCRYPTION OPTIONS - UNCOMMENT THE ONE REQUIRED BY THE QUESTION
                    # ------------------------------------------------------------------
                    ciphertext = des_encrypt(plaintext, des_key)                               # Option 1: DES ECB
                    # ciphertext = des_cbc_encrypt(plaintext, des_key)                          # Option 2: DES CBC
                    # ciphertext = des3_ecb_encrypt(plaintext, des3_key)                        # Option 3: 3DES ECB
                    # ciphertext = des3_cbc_encrypt(plaintext, des3_key)                        # Option 4: 3DES CBC
                    # ciphertext = aes_ecb_encrypt(plaintext, aes128_key)                       # Option 5: AES-128 ECB
                    # ciphertext = aes_encrypt(plaintext, aes128_key)                           # Option 6: AES-128 CBC
                    # ciphertext = aes_ecb_encrypt(plaintext, aes192_key)                       # Option 7: AES-192 ECB
                    # ciphertext = aes_encrypt(plaintext, aes192_key)                           # Option 8: AES-192 CBC
                    # ciphertext = aes_ecb_encrypt(plaintext, aes256_key)                       # Option 9: AES-256 ECB
                    # ciphertext = aes_encrypt(plaintext, aes256_key)                           # Option 10: AES-256 CBC
                    # ciphertext = caesar_encrypt(plaintext, additive_key)                      # Option 11: Caesar / Additive
                    # ciphertext = multiplicative_encrypt(plaintext, multiplicative_key)       # Option 12: Multiplicative
                    # ciphertext = affine_encrypt(plaintext, affine_k1, affine_k2)             # Option 13: Affine
                    # ciphertext = vigenere_encrypt(plaintext, vigenere_key)                   # Option 14: Vigenère
                    # ciphertext = rsa_encrypt(plaintext, rsa_pub)                               # Option 15: RSA Encryption

                    # ------------------------------------------------------------------
                    # HASH OPTIONS - UNCOMMENT THE ONE REQUIRED BY THE QUESTION
                    # ------------------------------------------------------------------
                    hash_val = get_sha256_hash(plaintext)  # Option 1: SHA-256 of original record
                    # hash_val = get_md5_hash(plaintext)                                    # Option 2: MD5
                    # hash_val = get_custom_hash(plaintext)                                 # Option 3: Custom Lab Hash

                    # ------------------------------------------------------------------
                    # ENCRYPTED RECORD HASH - used for signature generation
                    # ------------------------------------------------------------------
                    encrypted_hash = get_sha256_hash(ciphertext)  # Option 1: SHA-256
                    # encrypted_hash = get_md5_hash(ciphertext)   # Option 2: MD5
                    # encrypted_hash = get_custom_hash(ciphertext) # Option 3: Custom Lab Hash

                    # ------------------------------------------------------------------
                    # SIGNATURE GENERATION OPTIONS - UNCOMMENT ONE
                    # ------------------------------------------------------------------
                    signature = rsa_sign(encrypted_hash, rsa_priv)  # Option 1: RSA Signature
                    sig_type = "RSA"

                    # signature = ecc_sign(encrypted_hash, ecc_priv)  # Option 2: ECC Signature
                    # sig_type = "ECC"

                    # r_sig, s_sig = elgamal_sign(encrypted_hash, elgamal_pub, elgamal_priv) # Option 3: ElGamal Signature
                    # signature = f"{r_sig}:{s_sig}"
                    # sig_type = "ElGamal"

                    print(f">> Ciphertext Generated: {ciphertext}")
                    print(f">> Integrity Hash Generated: {hash_val}")
                    print(f">> Encrypted Record Hash: {encrypted_hash}")
                    print(f">> Digital Signature Generated: {str(signature)[:32]}...")

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    payload = {
                        "student_id": student_id,
                        "filename": filename,
                        "ciphertext": ciphertext,
                        "hash": hash_val,
                        "encrypted_hash": encrypted_hash,
                        "signature": signature,
                        "signature_type": sig_type,
                        "timestamp": timestamp,
                        "verification_result": None,
                        "verification_timestamp": None
                    }

                    save_to_db(payload)
                    print(
                        f">> Saved record '{filename}' successfully "
                        f"to database.json!"
                    )

                elif student_choice == '2':
                    student_id = input("Enter Student ID: ")
                    records = load_from_db()

                    my_records = [
                        r for r in records
                        if r.get("student_id") == student_id
                    ]

                    if not my_records:
                        print(">> No previous records found.")
                        continue

                    print("\n--- MY PREVIOUS RECORDS ---")
                    for idx, rec in enumerate(my_records, 1):
                        print(f"\n[{idx}] File: {rec['filename']}")
                        print(f"    Ciphertext: {rec['ciphertext']}")
                        print(f"    Hash: {rec['hash']}")
                        print(
                            f"    Encrypted Hash: "
                            f"{rec.get('encrypted_hash', 'N/A')}"
                        )
                        print(f"    Timestamp: {rec['timestamp']}")

                elif student_choice == '3':
                    break

                else:
                    print("Invalid Choice.")

        # ==============================================================
        # FACULTY
        # ==============================================================
        elif choice == '2':
            if not authenticate("faculty"):
                continue

            print("\n--- [ROLE 2: FACULTY] ---")
            records = load_from_db()

            if not records:
                print(">> Database file is empty.")
                continue

            print("Available Records:")
            for idx, rec in enumerate(records, 1):
                print(
                    f"{idx}. {rec['filename']} | "
                    f"Student: {rec.get('student_id', 'N/A')}"
                )

            try:
                record_choice = int(input("Select record number: "))
                if record_choice < 1 or record_choice > len(records):
                    print("Invalid record number.")
                    continue
            except ValueError:
                print("Invalid input.")
                continue

            selected = records[record_choice - 1]

            print(
                f"Loaded Record: {selected['filename']} "
                f"(Uploaded: {selected['timestamp']})"
            )
            print(f">> Ciphertext from File: {selected['ciphertext']}")
            print(f">> Stored Hash: {selected['hash']}")
            print(
                f">> Stored Encrypted-Record Hash: "
                f"{selected.get('encrypted_hash', 'N/A')}"
            )
            print(f">> Signature from File: {str(selected['signature'])[:32]}...")

            # ------------------------------------------------------------------
            # DYNAMIC KEY INPUTS FOR DECRYPTION (KEEP FOR CHANGED QUESTIONS)
            # ------------------------------------------------------------------

            # 1. DES Key Input (8 bytes)
            raw_des = input(
                "Enter 8-byte DES key used for decryption "
                "(Press Enter for default '8ByteKey'): "
            ) or "8ByteKey"
            des_key = raw_des[:8].ljust(8, '0').encode('utf-8')

            # 2. 3DES Key Input (16 or 24 bytes)
            # raw_3des = input("Enter 16 or 24-byte 3DES key for decryption: ") or "16ByteKey1234567"
            # des3_key = raw_3des[:16].ljust(16, '0').encode('utf-8')

            # 3. AES-128 Key Input (16 bytes)
            # raw_aes128 = input("Enter 16-byte AES key for decryption: ") or "16ByteKey1234567"
            # aes128_key = raw_aes128[:16].ljust(16, '0').encode('utf-8')

            # 4. AES-192 Key Input (24 bytes)
            # raw_aes192 = input("Enter 24-byte AES key for decryption: ") or "24ByteKey123456789012345"
            # aes192_key = raw_aes192[:24].ljust(24, '0').encode('utf-8')

            # 5. AES-256 Key Input (32 bytes)
            # raw_aes256 = input("Enter 32-byte AES key for decryption: ") or "32ByteKey1234567890123456789012"
            # aes256_key = raw_aes256[:32].ljust(32, '0').encode('utf-8')

            # 6. Caesar / Additive Shift Input
            # additive_key = int(input("Enter Additive Shift Key for decryption (Press Enter for 3): ") or "3")

            # 7. Multiplicative Key Input
            # multiplicative_key = int(input("Enter Multiplicative Key for decryption (Press Enter for 7): ") or "7")

            # 8. Affine Keys Input
            # affine_k1 = int(input("Enter k1 for decryption (default 7): ") or "7")
            # affine_k2 = int(input("Enter k2 for decryption (default 2): ") or "2")

            # 9. Vigenère Keyword Input
            # vigenere_key = input("Enter Vigenère Keyword for decryption (Press Enter for 'KEYWORD'): ") or "KEYWORD"

            # ------------------------------------------------------------------
            # DECRYPTION OPTIONS - UNCOMMENT THE ONE REQUIRED BY THE QUESTION
            # ------------------------------------------------------------------
            try:
                decrypted = des_decrypt(selected["ciphertext"], des_key)                          # Option 1: DES ECB
                # decrypted = des_cbc_decrypt(selected["ciphertext"], des_key)                    # Option 2: DES CBC
                # decrypted = des3_ecb_decrypt(selected["ciphertext"], des3_key)                  # Option 3: 3DES ECB
                # decrypted = des3_cbc_decrypt(selected["ciphertext"], des3_key)                  # Option 4: 3DES CBC
                # decrypted = aes_ecb_decrypt(selected["ciphertext"], aes128_key)                 # Option 5: AES-128 ECB
                # decrypted = aes_decrypt(selected["ciphertext"], aes128_key)                     # Option 6: AES-128 CBC
                # decrypted = aes_ecb_decrypt(selected["ciphertext"], aes192_key)                 # Option 7: AES-192 ECB
                # decrypted = aes_decrypt(selected["ciphertext"], aes192_key)                     # Option 8: AES-192 CBC
                # decrypted = aes_ecb_decrypt(selected["ciphertext"], aes256_key)                 # Option 9: AES-256 ECB
                # decrypted = aes_decrypt(selected["ciphertext"], aes256_key)                     # Option 10: AES-256 CBC
                # decrypted = caesar_decrypt(selected["ciphertext"], additive_key)               # Option 11: Caesar / Additive
                # decrypted = multiplicative_decrypt(selected["ciphertext"], multiplicative_key) # Option 12: Multiplicative
                # decrypted = affine_decrypt(selected["ciphertext"], affine_k1, affine_k2)       # Option 13: Affine
                # decrypted = vigenere_decrypt(selected["ciphertext"], vigenere_key)             # Option 14: Vigenère
                # decrypted = rsa_decrypt(selected["ciphertext"], rsa_priv)                       # Option 15: RSA Decryption
            except (ValueError, UnicodeDecodeError):
                print(">> Decryption failed. Wrong key or corrupted ciphertext.")
                continue

            print(f">> Decrypted Plaintext: {decrypted}")

            # ------------------------------------------------------------------
            # HASH VERIFICATION OPTIONS - UNCOMMENT THE ONE REQUIRED BY THE QUESTION
            # ------------------------------------------------------------------
            recomputed_hash = get_sha256_hash(decrypted)  # Option 1: SHA-256
            # recomputed_hash = get_md5_hash(decrypted)    # Option 2: MD5
            # recomputed_hash = get_custom_hash(decrypted) # Option 3: Custom Lab Hash

            print(f">> Recomputed Hash: {recomputed_hash}")
            valid_hash = (recomputed_hash == selected["hash"])
            print(
                f">> Hash Integrity Check: "
                f"{'INTACT' if valid_hash else 'CORRUPTED'}"
            )

            # ------------------------------------------------------------------
            # SIGNATURE VERIFICATION OPTIONS - UNCOMMENT ONE
            # ------------------------------------------------------------------
            valid_sig = rsa_verify(selected["encrypted_hash"], selected["signature"], rsa_pub) # Option 1: RSA
            # valid_sig = ecc_verify(selected["encrypted_hash"], selected["signature"], ecc_pub) # Option 2: ECC

            # Option 3: ElGamal
            # r_val, s_val = map(int, selected["signature"].split(":"))
            # valid_sig = elgamal_verify(selected["encrypted_hash"], (r_val, s_val), elgamal_pub)

            sig_type = selected.get("signature_type", "RSA")
            print(
                f">> Digital Signature Verification ({sig_type}): "
                f"{'SUCCESS' if valid_sig else 'FAILED'}"
            )

            # Store Faculty verification result with timestamp
            verification_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            selected["verification_result"] = {
                "hash_integrity": valid_hash,
                "signature_valid": valid_sig,
                "verified_by": "Faculty"
            }

            selected["verification_timestamp"] = verification_time

            with open(DB_FILE, "w") as f:
                json.dump(records, f, indent=4)

            print(
                f">> Verification result stored at: "
                f"{verification_time}"
            )

        # ==============================================================
        # HOD
        # ==============================================================
        elif choice == '3':
            if not authenticate("hod"):
                continue

            print("\n--- [ROLE 3: HoD] ---")
            records = load_from_db()

            if not records:
                print(">> Database file is empty.")
                continue

            print("\n--- HASHED ACADEMIC RECORDS ---")
            print(f">> Total Logged Entries: {len(records)}")

            for idx, rec in enumerate(records, 1):
                # --------------------------------------------------------------
                # SIGNATURE VERIFICATION OPTIONS - UNCOMMENT ONE
                # --------------------------------------------------------------
                valid_sig = rsa_verify(rec["encrypted_hash"], rec["signature"], rsa_pub) # Option 1: RSA
                # valid_sig = ecc_verify(rec["encrypted_hash"], rec["signature"], ecc_pub) # Option 2: ECC

                # Option 3: ElGamal
                # r_val, s_val = map(int, rec["signature"].split(":"))
                # valid_sig = elgamal_verify(rec["encrypted_hash"], (r_val, s_val), elgamal_pub)

                sig_type = rec.get("signature_type", "RSA")
                print(
                    f"[{idx}] File: {rec['filename']} | "
                    f"Type: {sig_type} | "
                    f"Hash: {rec['hash'][:16]}... | "
                    f"Timestamp: {rec['timestamp']} | "
                    f"Signature: {rec['signature']} | "
                    f"Sig Valid: {valid_sig}"
                )

        # ==============================================================
        # EXIT
        # ==============================================================
        elif choice == '4':
            print("Exiting System.")
            break

        else:
            print("Invalid Choice.")


if __name__ == "__main__":
    main_system()