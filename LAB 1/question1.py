inp = input("Enter something: ")

multiInverse = {1:1, 3:9, 5:21, 7:15, 11:19, 17:23, 9:3, 15:7, 19:11, 21:5, 23:17, 25:25}

filtered_inp = ""
for char in inp:
    if char!=' ':
        filtered_inp+=char

# Additive cipher KEY=20
key = 20

encrypted_inp_additive = ""
filt = 'A'

for char in filtered_inp:
    if ord(char)>=ord('A') and ord(char)<=ord('Z'):
        filt='A'
    else :
        filt='a'
    encrypted_char=ord(char)-ord(filt)
    encrypted_char=(encrypted_char+key)%26
    encrypted_inp_additive+=chr(encrypted_char+ord(filt))
    # print(encrypted_char)

decrypted_inp_additive = ""
for char in encrypted_inp_additive:
    if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
        filt='A'
    else:
        filt='a'
    decrypted_char=ord(char)-ord(filt)
    decrypted_char=(decrypted_char-key)%26
    decrypted_inp_additive+=chr(decrypted_char+ord(filt))

print("Encrypted Text using Additive cipher: "+encrypted_inp_additive)
print("Decrypted Text using Additive cipher: "+decrypted_inp_additive)

# Multiplicative cipher KEY=15
key=15

encrypted_inp_multi = ""
for char in filtered_inp:
    if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
        filt='A'
    else:
        filt='a'
    encrypted_char=ord(char)-ord(filt)
    encrypted_char=(encrypted_char*key)%26
    encrypted_inp_multi+=chr(encrypted_char+ord(filt))

decrypted_inp_multi = ""
for char in encrypted_inp_multi:
    if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
        filt='A'
    else:
        filt='a'
    decrypted_char=ord(char)-ord(filt)
    decrypted_char=(decrypted_char*multiInverse[key])%26
    decrypted_inp_multi+=chr(decrypted_char+ord(filt))

print("Encrypted Text using Multiplicative cipher : "+encrypted_inp_multi)
print("Decrypted Text using Multiplicative cipher: "+decrypted_inp_multi)

# Affeine cipher KEY: (15, 20)
key1 = 15
key2 = 20

encrypted_inp_affine = ""
for char in filtered_inp:
    if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
        filt='A'
    else:
        filt='a'
    encrypted_char=ord(char)-ord(filt)
    encrypted_char=(encrypted_char*key1+key2)%26
    encrypted_inp_affine+=chr(encrypted_char+ord(filt))

decrypted_inp_affine = ""
for char in encrypted_inp_affine:
    if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
        filt='A'
    else:
        filt='a'
    decrypted_char=ord(char)-ord(filt)
    decrypted_char=((decrypted_char-key2)*multiInverse[key1])%26
    decrypted_inp_affine+=chr(decrypted_char+ord(filt))
print("Encrypted Text using Affine cipher : "+encrypted_inp_affine)
print("Decrypted Text using Affine cipher: "+decrypted_inp_affine)