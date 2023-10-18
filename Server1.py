from pymongo import MongoClient
from pprint import pprint
from crypto.python import EccCore
import hashlib
import random
import numpy as np
import math

# Choose the appropriate client
client = MongoClient("mongodb+srv://Cluster73137:S3PNMwUmMaAQpzPI@cluster73137.l29srvj.mongodb.net/")
db=client.server1

mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337


a = 0
b = 7

G1=[55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424]
G2=[123,98]
G3=[2,24]
G4=[540,240]
x1= 2010000000000017
G1X1, G1Y1 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x1, a, b, mod)
x2 = 2010000000000061
G1X2, G1Y2 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x2, a, b, mod)
print("Server 1 public key: (",G1X1,", ", G1Y1,")")
Server1PublicKey= db.Server1PublicKey
PublicKeyDetails = {
        'X-coordinate': str(G1X1),
        'Y-coordinate': str(G1Y1)
    }

    # Use the insert method
result = Server1PublicKey.insert_one(PublicKeyDetails)


def get_area(x,y):
    area=0.5*( (x[0]*(y[1]-y[2])) + (x[1]*(y[2]-y[0])) + (x[2]*(y[0]-y[1])) )
    return int(area)

def getcofactor(m, i, j):
    return [row[: j] + row[j+1:] for row in (m[: i] + m[i+1:])]
    
    # defining the function to
    # calculate determinant value
    # of given matrix a.
    
    
def determinantOfMatrix(mat):    
    if(len(mat) == 2):
        value = mat[0][0] * mat[1][1] - mat[1][0] * mat[0][1]
        return value
    
    
    Sum = 0
    
    
    for current_column in range(len(mat)):    
        sign = (-1) ** (current_column)
    
        sub_det = determinantOfMatrix(getcofactor(mat, 0, current_column))
        Sum += (sign * mat[0][current_column] * sub_det)
    return Sum

def change_to_be_hex(s):
    return int(s,base=16)
        
def xor_two_str(str1,str2):
    a = change_to_be_hex(str1)
    b = change_to_be_hex(str2)
    return hex(a ^ b)

# Connect to the test db 


def ComputeCircumcenter(G3X1,G3Y1,to_register):  
    a = 0
    b = 7  
    mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
    order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    G4X1,G4Y1=EccCore.pointAddition(540, 424, G3X1, G3Y1, a, b, mod)
    x=[]
    y=[]
    z=[]
    st1=str(G4X1)
    st2=str(G4Y1)
    st3=str(G4X1+G4Y1)
    x.append(int(st1[0:28]))
    x.append(int(st1[28:55]))
    x.append(int(st1[55:]))
    y.append(int(st2[0:28]))
    y.append(int(st2[28:55]))
    y.append(int(st2[55:]))
    z.append(int(st3[0:28]))
    z.append(int(st3[28:55]))
    z.append(int(st3[55:]))

    # x_half=G3X1//9
    # x.append(x_half)
    # x.append(x_half*7)
    # x.append(x_half*2)
    # y_half=G3Y1//9
    # y.append(y_half*3)
    # y.append(y_half*4)
    # y.append(y_half*2)
    # z_half=(G3X1+G3Y1)//9
    # z.append(z_half*1)
    # z.append(z_half*2)
    # z.append(z_half*6)
    A=[]
    B=[]
    C=[]
    A.append(x[0])
    A.append(y[0])
    A.append(z[0])

    B.append(x[1])
    B.append(y[1])
    B.append(z[1])

    C.append(x[2])
    C.append(y[2])
    C.append(z[2])

    D=[]
    # print(x[0],x[1],x[2])
    # D_x=(x[0]+x[1]+x[2])//3
    # D_y=(y[0]+y[1]+y[2])//3
    # D_z=(z[0]+z[1]+z[2])//3

    # D.append(D_x)
    # D.append(D_y)
    # D.append(D_z)

    A=np.array(A)
    B=np.array(B)
    C=np.array(C)
    D.append((A[0]+B[0]+C[0])//3)
    D.append((A[1]+B[1]+C[1])//3)
    D.append((A[2]+B[2]+C[2])//3)
    D=np.array(D)
    D/=3
    # print(D)
    tmp_1=B-A
    tmp_2=C-A
    tmp_1=np.array(tmp_1)
    tmp_2=np.array(tmp_2)
    # print(tmp_1*tmp_2)
    square = np.square(tmp_1 -tmp_2)
    # Get the sum of the square
    sum_square = np.sum(square)
    distance = (sum_square)**0.5
    # print('Distance-->',distance)

    distance=distance*(2/3)**(0.5)
    # D+=distance
    D+=distance

    t=[]
    print("Points of the Tetrahedron: -")
    print('Point A:(',end=" ")
    print(A[0],',',A[1],' ,',A[2],')')
    print('Point B:(',end=" ")
    print(B[0],',',B[1],' ,',B[2],')')
    print('Point C:(',end=" ")
    print(C[0],',',C[1],' ,',C[2],')')
    print('Point D:(',end=" ")
    print(D[0],',',D[1],' ,',D[2],')')
    # print(D_x)
    # print(D_y)
    # print(D_z)
    # # print("\n")
    print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    for i in range(0,3):
        t.append(abs(A[i]-D[i]))
        

    u=[]
    for i in range(0,3):
        u.append(abs(B[i]-D[i]))
        
    v=[]
    for i in range(0,3):
        v.append(abs(C[i]-D[i]))
        

    circumcenter=D
    n_array = []
    n_array.append(t)
    n_array.append(u)
    n_array.append(v)

    dist_t=0
    for i in range(len(D)):
        dist_t+=(abs(A[i]-D[i]))

    dist_u=0
    for i in range(len(D)):
        dist_u+=(abs(B[i]-D[i]))

    dist_v=0
    for i in range(len(D)):
        dist_v+=(abs(C[i]-D[i]))




    deter=determinantOfMatrix(n_array)
    # print(D[0])
    # print(D[1])
    # print(D[2])
    # for r in n_array:
    #    for c in r:
    #       print(c,end = " ")
    #    print()
    u=np.array(u)
    v=np.array(v)
    t=np.array(t)
    temp_u=np.array(u)
    temp_v=np.array(v)
    temp_t=np.array(t)
    for i in temp_t:
        temp_t*=(dist_v**2)
    temp_t*=u

    for i in temp_u:
        temp_u*=(dist_t**2)
    temp_u*=v
    for i in temp_v:
        temp_v*=(dist_u**2)
    temp_v*=t
    # temp_u*=(dist_t**2)
    # temp_u*=v
    # temp_t*=(dist_v**2)
    # temp_t*=u
    # temp_v*=(dist_u**2)
    # temp_v*=t

    # print(temp_t[0],' ',temp_t[1],' ',temp_t[2])
    temp=temp_t+temp_u+temp_v
    temp/=(2*deter)
    # print(temp[0])
    # print(temp[1])
    # print(temp[2])
    circumcenter=np.array(circumcenter)
    circumcenter+=temp
    
    print('Circumcenter:(',end=" ")
    print(circumcenter[0],',',circumcenter[1],' ,',circumcenter[2],')')
    a2=random.getrandbits(512)
    M1=[4,9]
    A2=list(EccCore.applyDoubleAndAddMethod(G1[0], G1[1], a2, a, b, mod))
    M1=np.array(M1)
    B2=M1+(a2*G1Y2)

    Points=db.Points
    A2[0]=str(A2[0])
    A2[1]=str(A2[1])
    B2[0]=str(B2[0])
    B2[1]=str(B2[1])
    
    var={'A2-x':A2[0],'A2-y':A2[1],'B2-x':B2[0],'B2-y':B2[1]}
    
    if(to_register):
        result = Points.insert_one(var)
        addCircumcentreinServer(circumcenter)
    else:
        return checkwithCircumcentre(circumcenter)

    
def addCircumcentreinServer(circumcentre_values):
    circumcentre= db.circumcentre
    circumcentre_details = {
        'X-coordinate': circumcentre_values[0],
        'Y-coordinate': circumcentre_values[1],
        'Z-coordinate': circumcentre_values[2]
    }

    # Use the insert method
    result = circumcentre.insert_one(circumcentre_details)
    return True
    # Query for the inserted document.
    # Queryresult = employee.find_one({'Age':})
    # pprint(Queryresult)

def checkwithCircumcentre(circumcentre_values):
    circumcentre=db.circumcentre
    Queryresult=circumcentre.find_one({'X-coordinate':circumcentre_values[0]})
    return (Queryresult!=None)    