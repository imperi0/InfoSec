from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad


# ============================================================
# INPUT
# ============================================================

message = "Top Secret Data"

key_hex = "FEDCBA9876543210FEDCBA9876543210"


# ============================================================
# PAD KEY TO AES-192 (24 BYTES)
# ============================================================

key = bytes.fromhex(key_hex)

print("Original key length:", len(key), "bytes")

# AES-192 requires 24 bytes
if len(key) < 24:
    key = key + b"\x00" * (24 - len(key))

print("Padded key length  :", len(key), "bytes")
print("Padded AES-192 key :", key.hex().upper())


# ============================================================
# AES S-BOX
# ============================================================

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]


# ============================================================
# RCON
# ============================================================

RCON = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36
]


# ============================================================
# KEY EXPANSION
# ============================================================

def rot_word(word):
    return word[1:] + word[:1]


def sub_word(word):
    return [S_BOX[x] for x in word]


def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]


def key_expansion(key):

    # AES-192:
    # Nk = 6
    # Nb = 4
    # Nr = 12

    Nk = 6
    Nb = 4
    Nr = 12

    total_words = Nb * (Nr + 1)

    words = []

    # First 6 words
    for i in range(Nk):
        words.append(
            list(key[4 * i:4 * i + 4])
        )

    for i in range(Nk, total_words):

        temp = words[i - 1].copy()

        if i % Nk == 0:

            temp = rot_word(temp)
            temp = sub_word(temp)

            temp[0] ^= RCON[i // Nk]

        words.append(
            xor_words(
                words[i - Nk],
                temp
            )
        )

    return words


# ============================================================
# ROUND KEYS
# ============================================================

def get_round_keys(words):

    round_keys = []

    for r in range(13):

        round_key = []

        for word in words[4*r:4*r+4]:
            round_key.extend(word)

        round_keys.append(round_key)

    return round_keys


# ============================================================
# AES OPERATIONS
# ============================================================

def add_round_key(state, key):

    for i in range(16):
        state[i] ^= key[i]


def sub_bytes(state):

    for i in range(16):
        state[i] = S_BOX[state[i]]


def shift_rows(state):

    temp = state.copy()

    for row in range(4):

        for col in range(4):

            state[4*col + row] = \
                temp[4*((col + row) % 4) + row]


def gmul(a, b):

    result = 0

    for _ in range(8):

        if b & 1:
            result ^= a

        high = a & 0x80

        a <<= 1

        if high:
            a ^= 0x1B

        a &= 0xFF
        b >>= 1

    return result


def mix_columns(state):

    for col in range(4):

        i = 4 * col

        a0 = state[i]
        a1 = state[i + 1]
        a2 = state[i + 2]
        a3 = state[i + 3]

        state[i] = (
            gmul(a0, 2) ^
            gmul(a1, 3) ^
            a2 ^
            a3
        )

        state[i+1] = (
            a0 ^
            gmul(a1, 2) ^
            gmul(a2, 3) ^
            a3
        )

        state[i+2] = (
            a0 ^
            a1 ^
            gmul(a2, 2) ^
            gmul(a3, 3)
        )

        state[i+3] = (
            gmul(a0, 3) ^
            a1 ^
            a2 ^
            gmul(a3, 2)
        )


def show(label, state):

    print(
        f"{label:<25}: "
        + bytes(state).hex().upper()
    )


# ============================================================
# AES-192 ENCRYPTION
# ============================================================

def aes_192_encrypt(block, key):

    # --------------------------------------------------------
    # KEY EXPANSION
    # --------------------------------------------------------

    words = key_expansion(key)

    print("\n")
    print("=" * 70)
    print("KEY EXPANSION")
    print("=" * 70)

    for i, word in enumerate(words):

        print(
            f"W{i:02d}: "
            + "".join(f"{x:02X}" for x in word)
        )


    # --------------------------------------------------------
    # ROUND KEYS
    # --------------------------------------------------------

    round_keys = get_round_keys(words)

    print("\n")
    print("=" * 70)
    print("ROUND KEYS")
    print("=" * 70)

    for i, rk in enumerate(round_keys):

        print(
            f"K{i:02d}: "
            + bytes(rk).hex().upper()
        )


    # --------------------------------------------------------
    # INITIAL ROUND
    # --------------------------------------------------------

    state = list(block)

    print("\n")
    print("=" * 70)
    print("INITIAL ROUND")
    print("=" * 70)

    show("Input", state)

    add_round_key(
        state,
        round_keys[0]
    )

    show("After AddRoundKey", state)


    # --------------------------------------------------------
    # MAIN ROUNDS 1 - 11
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("MAIN ROUNDS")
    print("=" * 70)

    for r in range(1, 12):

        print(f"\n----- ROUND {r} -----")

        sub_bytes(state)

        show(
            "After SubBytes",
            state
        )

        shift_rows(state)

        show(
            "After ShiftRows",
            state
        )

        mix_columns(state)

        show(
            "After MixColumns",
            state
        )

        add_round_key(
            state,
            round_keys[r]
        )

        show(
            "After AddRoundKey",
            state
        )


    # --------------------------------------------------------
    # FINAL ROUND
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("FINAL ROUND 12")
    print("=" * 70)

    sub_bytes(state)

    show(
        "After SubBytes",
        state
    )

    shift_rows(state)

    show(
        "After ShiftRows",
        state
    )

    # NO MixColumns in final round

    add_round_key(
        state,
        round_keys[12]
    )

    show(
        "After AddRoundKey",
        state
    )

    return bytes(state)


# ============================================================
# MAIN PROGRAM
# ============================================================

print("=" * 70)
print("AES-192 ENCRYPTION")
print("=" * 70)

print("\nMessage:")
print(message)

print("\nOriginal Key:")
print(key_hex)

print("\nPadded AES-192 Key:")
print(key.hex().upper())


# ============================================================
# PLAINTEXT PADDING
# ============================================================

plaintext = message.encode("utf-8")

padded_plaintext = pad(
    plaintext,
    AES.block_size
)

print("\nPadded Plaintext:")
print(
    padded_plaintext.hex().upper()
)


# ============================================================
# ENCRYPT
# ============================================================

ciphertext = aes_192_encrypt(
    padded_plaintext,
    key
)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n")
print("=" * 70)
print("FINAL CIPHERTEXT")
print("=" * 70)

print(
    ciphertext.hex().upper()
)


# ============================================================
# VERIFY AGAINST PYCRYPTODOME
# ============================================================

cipher = AES.new(
    key,
    AES.MODE_ECB
)

expected = cipher.encrypt(
    padded_plaintext
)

print("\n")
print("=" * 70)
print("VERIFICATION")
print("=" * 70)

print(
    "Our ciphertext       :",
    ciphertext.hex().upper()
)

print(
    "PyCryptodome result  :",
    expected.hex().upper()
)

print(
    "Match                :",
    ciphertext == expected
)