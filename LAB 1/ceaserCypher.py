import hashlib
from email import message


def sha256_hash(text):
    hash_value = hashlib.sha256(text.encode())
    return hash_value.hexdigest()

text=input("Enter the text to encrypt: ")

def encrypt(text):
    encrypted_text=""
    key = 4
    for c in text:
        if 'a'<=c<='z':
            encrypted_text+=chr((ord(c) - ord('a') + key)%26 + ord('a'))

        elif 'A'<=c<='Z':
            encrypted_text+=chr((ord(c) - ord('A') + key)%26 + ord('A'))

        else:
            encrypted_text+=c
    return encrypted_text

def decrypt(text):
    decrypted_text=""
    key = 4
    for c in text:
        if 'a'<=c<='z':
            decrypted_text+=chr((ord(c) - ord('a') - key)%26 + ord('a'))

        elif 'A'<=c<='Z':
            decrypted_text+=chr((ord(c) - ord('A') - key)%26 + ord('A'))

        else:
            decrypted_text+=c
    return decrypted_text

def check_integrity(text, result):
    hash_value = hashlib.sha256(text.encode()).hexdigest()
    return hash_value==result;

print(encrypt(text))
print(decrypt(encrypt(text)))

message=encrypt(text)
result = sha256_hash(message)
print("SHA-256 Hash:", result)

if(check_integrity(encrypt(text), result)):
    print("Hash matches")
else:
    print("Hash does not match")