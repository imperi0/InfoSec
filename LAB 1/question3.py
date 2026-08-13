from curses.ascii import islower, isupper

playfair_matrix = [
    ['g', 'u', 'i', 'd', 'a'],
    ['n', 'c', 'e', 'b', 'f'],
    ['h', 'k', 'l', 'o', 'p'],
    ['q', 'r', 's', 't', 'v'],
    ['w', 'x', 'y', 'z', 'm'],
]

pos_map={}

for r in range(len(playfair_matrix)):
  for c in range(len(playfair_matrix[r])):
    letter=playfair_matrix[r][c]
    pos_map[letter]=(r,c)

inp=input("Enter the text : ")

filtered_text=""
for i in inp:
    if islower(i):
        filtered_text=filtered_text+i
    elif isupper(i):
        filtered_text=filtered_text+i.lower()

def find_enc(c1, c2):
    ret=""

    if c1=='j':
        c1='i'
    if c2=='j':
        c2='i'

    a1,b1=pos_map[c1]
    a2,b2=pos_map[c2]

    if a1==a2:
        ret+=playfair_matrix[a1][(b1+1)%5]
        ret+=playfair_matrix[a2][(b2+1)%5]
        return ret

    if b1==b2:
        ret+=playfair_matrix[(a1+1)%5][b1]
        ret+=playfair_matrix[(a2+1)%5][b2]
        return ret

    ret+=playfair_matrix[a1][b2]
    ret+=playfair_matrix[a2][b1]

    return ret

def find_dec(c1, c2):
    ret=""

    if c1=='j':
        c1='i'
    if c2=='j':
        c2='i'

    a1,b1=pos_map[c1]
    a2,b2=pos_map[c2]

    if a1==a2:
        ret+=playfair_matrix[a1][(b1-1)%5]
        ret+=playfair_matrix[a2][(b2-1)%5]
        return ret

    if b1==b2:
        ret+=playfair_matrix[(a1-1)%5][b1]
        ret+=playfair_matrix[(a2-1)%5][b2]
        return ret

    ret+=playfair_matrix[a1][b2]
    ret+=playfair_matrix[a2][b1]

    return ret

def encrypt(text):
    encrypted_text=""
    pairs=[]
    app=""
    for i in text:
        if app=="":
            app=i
        else:
            if app[0]==i:
                app+='x'
                pairs.append(app)
                app=i
            else :
                app+=i
                pairs.append(app)
                app=""
    if app!="":
        pairs.append(app+'x')

    for i,j in pairs:
        enc=find_enc(i,j)
        encrypted_text=encrypted_text+enc

    return encrypted_text

def decrypt(text):
    pairs = []
    app = ""
    decrypted_text=""

    for i in text:
        if app == "":
            app = i
        else:
            app+=i
            pairs.append(app)
            app=""

    for i,j in pairs:
        dec=find_dec(i,j)
        decrypted_text=decrypted_text+dec

    return decrypted_text

encrypted_text_sui=encrypt(filtered_text)
print(f"Encrypted text : {encrypted_text_sui}")
print(f"Decrypted text : {decrypt(encrypted_text_sui)}")