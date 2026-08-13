from curses.ascii import islower, isupper

inp=input("Enter the text : ")
key=13

filtered_text=""
for i in inp:
    if islower(i):
        filtered_text=filtered_text+i
    elif isupper(i):
        filtered_text=filtered_text+i.lower()


def encrypt(text):
    temp_key=key
    encrypted_text=""
    for i in text:
        enc=chr((ord(i)-ord('a')+temp_key)%26+ord('a'))
        encrypted_text=encrypted_text+enc
        temp_key=ord(i)-ord('a')
    return encrypted_text

def decrypt(text):
    temp_key=key
    decryted_text=""
    for i in text:
        dec=chr((ord(i)-ord('a')-temp_key)%26+ord('a'))
        decryted_text=decryted_text+dec
        temp_key=ord(dec)-ord('a')
    return decryted_text

encrypted_text_sui=encrypt(filtered_text)
print(f"Encrypted text : {encrypted_text_sui}")
print(f"Decrypted text : {decrypt(encrypted_text_sui)}")