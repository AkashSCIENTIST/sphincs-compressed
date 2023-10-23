# from pymongo import MongoClient
from pprint import pprint
import math
from crypto.python import EccCore
import random
import numpy as np
# from sibc.sidh import SIKE, default_parameters
from pymongo import MongoClient
from package.sphincs import Sphincs


# Choose the appropriate client
# client = MongoClient()
G1=[55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424]
G2=[123,98]
G3=[2,24]
G4=[540,240]
mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337


a = 0
b = 7
    
# Connect to the test db 
client = MongoClient(
    "mongodb+srv://Cluster73137:S3PNMwUmMaAQpzPI@cluster73137.l29srvj.mongodb.net/")
# db = client.VoiceAssistant
db=client.server2

x1= 2010000000000017
G1X1, G1Y1 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x1, a, b, mod)
x2 = 2010000000000061
G1X2, G1Y2 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x2, a, b, mod)
print("Server 2 public key: (",G1X2,", ", G1Y2,")")
# Server2PublicKey= db.Server2PublicKey
PublicKeyDetails = {
        'X-coordinate': str(G1X2),
        'Y-coordinate': str(G1Y2)
    }

    # Use the insert method
# result = Server2PublicKey.insert_one(PublicKeyDetails)
def add_block(block):
    pass
#     Blockchain= db.Blockchain
#     result=Blockchain.insert_one(block)
# sike = SIKE(**default_parameters)        
def digitalSignature(val,c,sphincs):
    value=c.encode(encoding="UTF-8")
    sig = sphincs.sign(value,val[0])
    return sphincs.verify(value,sig,val[1])
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

def angle(k,l,m,n):
    n1=k-l
    m1=m-n

    n1*=m1
    square = np.square(n1 - m1)

    sum_square = np.sum(square)
    distance = (sum_square)**0.5
    n1/=distance
    dotproduct=0
    for i in n1:
        dotproduct+=i
    dotproduct/=3
        # print(dotproduct)
    return math.degrees(math.acos(float(dotproduct)))

def ComputeAngleBetweenMedians(G3X1,G3Y1,to_register):
    mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
    order = 115792089237316195423570985008687907852837564279074904382605163141518161494337



    a = 0
    b = 7
    
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
    # print("Points of the Tetrahedron: -")
    # print('Point A:(',end=" ")
    # print(A[0],',',A[1],' ,',A[2],')')
    # print('Point B:(',end=" ")
    # print(B[0],',',B[1],' ,',B[2],')')
    # print('Point C:(',end=" ")
    # print(C[0],',',C[1],' ,',C[2],')')
    # print('Point D:(',end=" ")
    # print(D[0],',',D[1],' ,',D[2],')')
    angle1=angle(A,B,C,D)
    angle2=angle(A,C,B,D)
    angle3=angle(A,D,B,C)
    G2=[123,98]
    # G2X1,G2Y1=EccCore.applyDoubleAndAddMethod(G2[0],G2[1],p,a,b,mod)
    print('Angle in Radians:',(angle1+angle2+angle3)//3)
    
    a1=random.getrandbits(512)
    M2=[40,24]
    M2=np.array(M2)
    A1=list(EccCore.applyDoubleAndAddMethod(G1[0], G1[1], a1, a, b, mod))
    B1=M2+(a1*G1Y1)
    Points=db.Points
    # Points = []
    A1[0]=str(A1[0])
    A1[1]=str(A1[1])
    B1[0]=str(B1[0])
    B1[1]=str(B1[1])
    
    var={'A1-x':A1[0],'A1-y':A1[1],'B1-x':B1[0],'B1-y':B1[1]}
    if(to_register):
        result = Points.insert_one(var)
        # result = Points + [var]
        addAngleinServer((angle1+angle2+angle3)//3)
    else:
        return checkwithAngle((angle1+angle2+angle3)//3)

    
def addAngleinServer(angle_values):
    Angle= db.Angle
    # Angle = []
    angle_details = {
        'Angle-in-radians': math.radians(angle_values),
        'Angle-in-values': (angle_values)
    }

    # Use the insert method
    result = Angle.insert_one(angle_details)
    # result = Angle + [angle_details]

    # Query for the inserted document.
    # Queryresult = employee.find_one({'Age':})
    # pprint(Queryresult)

def checkwithAngle(angle_values):
    Angle=db.Angle
    # Angle = []
    Queryresult=Angle.find_one({'Angle-in-values':angle_values})
    return (Queryresult!=None)    
