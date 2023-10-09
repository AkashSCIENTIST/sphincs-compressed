import matplotlib.pyplot as plt
import numpy as np
import time
#initialising all the values for ECC encryption
bit = []
g = 360
na = 1905302
nb = 1905215
pa = na*g
pb = nb*g
k=na*pb
ex = k*g


def inv(x,y):      #Finds Multiplicative inverse
    flag = 0
    m = 1
    while(flag!=1):
        r = (x*m)%y
        if (r==1):
            flag = 1
        m = m + 1
    return(m-1)

def ec(pt):    #Rabin encryption for number ; returns an Integer value
    p=23
    q=7
    e = 2
    n = p*q
    ct = (pt**e) % n
    return ct

def dc(ct,pt):     #Rabin decryption for number
    p=23
    q=7
    e = 2
    n = p*q
    a1 = (ct**((p+1)/4))%p
    a2 = p-a1
    b1 = (ct**((q+1)/4))%q
    b2 = q - b1
    a = q* inv(q,p)
    b = p * inv(p,q)
    p1 = (a*a1 + b*b1)%n
    p2 = (a*a1 + b*b2)%n
    p3 = (a*a2 + b*b1)%n
    p4 = (a*a2 + b*b2)%n
    if(pt == p1):
        return p1
    elif(pt == p2):
        return p2
    elif(pt == p3):
        return p3
    elif(pt == p4):
        return p4
    else:
        print("error")
        
def utf(msg): #Converting a string to a set of utf values; returns array of numbers ; size is reduced ; utf is for strings not integers 
    cipher = []
    for part in msg:
        pm = ord(part)
        cipher.append(pm)
    return cipher

def deutf(fa):    #Reconverting the utf values to strings
    msg = ""
    sz = len(fa)
    for vi in range(0,sz):
        c = chr(fa[vi])
        msg = msg + c
    return msg

def rencec(msg):   #Rabin string encryption ; returns array of numbers
    x = utf(msg)
    sz = len(x)
    y = []
    for i in range(0,sz):
        y.append(ec(x[i]))
    return y

def reimg(px,x,y):  #Converts pixel values to image
    size = (x,y,3)
    newarray = np.reshape(px,size)
    plt.imshow(newarray)

def redec(y,sec):  #Rabin string decryption
    z = []
    sz = len(y)
    for i in range(0,sz):
        z.append(dc(y[i],sec[i]))
    for i in range(0,sz):
        z[i]=int(z[i])
    ss = deutf(z)
    return ss

def flatten(l):   # Jagged matrix to 1D array 
    lf=[]
    li=[]
    ll=[]
    lf1= []
    p=0
    for i in l:
        if type(i).__name__=='list':
            li.append(i)
        else:
               lf.append(i)
    ll=[x for i in li for x in i]
    lf.extend(ll)

    for i in lf:
        if type(i).__name__ =='list':   
            flatten(lf)
        else:
            p=p+1
            continue

    if p==len(lf):
        lf1 = lf
    return lf1

def reframe(tst,sz): #1D array to 3D mtrix
    i=0
    x = []
    while(i!=(3*sz)):
        y=[]
        y.append(tst[i])
        y.append(tst[i+1])
        y.append(tst[i+2])
        i=i+3
        x.append(y)
    return x
def PSNR(original,recreated,sz):    #Finding peak to noise ratio (PSNR)
    cnt=0
    for i in range(0,sz):
        if(original[i] == recreated[i]):
            cnt = cnt + 1
    score = (cnt)/sz
    per = score*100
    return per
def rabin_enc_img(carr,sz,x,y):     #Finding out Rabin encrypted image
    tst = flatten(carr)
    reimg(tst[:sz],y,x)
    return tst
def ecc_enc_img(ee,sz,x,y):        #Finding out ECC encrypted image
    t11 = []
    for i in range(0,len(ee)):
        t11.append(ee[i]%256)
    reimg(t11[5*sz:6*sz],y,x) #6sz - 5sz
def ecc_enc(cipher,n):        #ECC array Encrytion
    exa = []
    eya = []
    for vi in range(0,n):
        pm = cipher[vi]
        ex = k*g
        ey = pm + k*pb
        exa.append(ex)
        eya.append(ey)
    ret = exa + eya
    return ret
def rabin_enc(arr,sz):  #Rabin Image Encrytion
    arrc = [] # arrc for characters
    sz = len(arr)
    for i in range(0,sz):
        arrc.append(str(arr[i]))
    
    for i in range(0,sz):
        if(len(arrc[i])==1):
            arrc[i] = "00"+arrc[i]
        if(len(arrc[i])==2):
            arrc[i] = "0"+arrc[i]
    
    global bit
    sz1 = len(arrc)
    for i in range(0,sz):
        bit.append(utf(arrc[i]))
        
    carr = []
    for i in range(0,sz):
        carr.append(rencec(arrc[i]))
    return carr

def rabin_dec(t2,sz):  #Rabin Image Decrytion
    tt = reframe(t2)
    tl = len(tt)
    ffn = []
    for i in range(0,tl):
        ffn.append(redec(tt[i],bit[i]))
    farrn=[]
    for i in range(0,tl):
        farrn.append(int(ffn[i]))
        
    global sval
    farrn = farrn - sval
    for i in range(0,sz):
        if(farrn[i]<0):
            farrn[i] = farrn[i]+256
    return farrn
def ecc_dec(code,n):       #ECC array Decrytion
    dx = []
    for vi in range(0,n):
        s1 = code[vi]*nb ##code[vi] = x
        store = code[n+vi]-s1 ##code[len(code)/2 + vi] = y
        dx.append(store)
    return dx

def encrypt(img):
    x,y = img.size
    time.sleep(1)
    i = np.array(img)
    arr=i.ravel()
    sz = x*y*3
    arr  = np.reshape(i,sz)
    sval  = arr[100]
    arr1 = arr + sval
    start = time.time()
    start1=round(time.time()*1000)
    re = rabin_enc(arr1,sz)
    end = time.time()
    flat_re = rabin_enc_img(re,sz,x,y)
    ee = ecc_enc(flat_re,len(flat_re))
    end = time.time()
    end1=round(time.time()*1000)
    t = end - start
    t1=end1-start1
    m = int(t//60)
    s = int(t%60)
    return ecc_enc_img(ee,sz,x,y)

