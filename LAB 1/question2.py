inp = input()

key = "dollars"

filtered_text=""
for char in inp:
    if(char!=' ') :
        filtered_text+=char

j=0
encrypted_inp=""
filt='A'

for char in filtered_text:
    if ord(char)>=ord('a') and ord(char)<=ord('z'):
        filt='a'
    else:
        filt='A'
    encrypted_char=ord(char)-ord(filt)
    keyj=ord(key[j])-ord(filt)

# Continue and complete this later