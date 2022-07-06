import base64
with open("1.txt","rb") as f:
    all=f.read()
    array=[]
    for i in all:
        array.append(i^8)
    #print(bytearray(array))
    print(base64.b64encode(bytearray(array)))