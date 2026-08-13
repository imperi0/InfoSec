# key1 = 15
# key2 = 20

multiInverse = {1:1, 3:9, 5:21, 7:15, 11:19, 17:23, 9:3, 15:7, 19:11, 21:5, 23:17, 25:25}

text=input("Enter Text : ")

# encrypted_inp_affine = ""
# for char in text:
#     if(ord(char)>=ord('A') and ord(char)<=ord('Z')):
#         filt='A'
#     else:
#         filt='a'
#     encrypted_char=ord(char)-ord(filt)
#     encrypted_char=(encrypted_char*key1+key2)%26
#     encrypted_inp_affine+=chr(encrypted_char+ord(filt))

def decrypt(text,key1, key2):
    decrypted_inp_affine=""
    for char in text:
        char=char.upper()
        filt='A'
        decrypted_char = ord(char) - ord(filt)
        decrypted_char = ((decrypted_char - key2) * multiInverse[key1]) % 26
        decrypted_inp_affine += chr(decrypted_char + ord(filt))
    return decrypted_inp_affine

def brute_it_suiii(text):
    ret=""
    k2range=[1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for i in k2range:
        for j in range(26):
            temp=decrypt("GL",i,j)
            if temp=="AB":
                key1=i
                key2=j
                print(i,j)
                return i,j
    return -1,-1

k1,k2=brute_it_suiii(text)
decrypted_inp_affine=decrypt(text, k1, k2)
print("Decrypted Text using Affine cipher: "+decrypted_inp_affine)