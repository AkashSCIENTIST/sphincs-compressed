import crypto.python.EccCore as EccCore
import hashlib
import random
import numpy as np
import math
import sys
applyKeyExchange = True
sys.path.insert(0,'sibc')

from Server1 import addCircumcentreinServer,ComputeCircumcenter
from Server2 import addAngleinServer,ComputeAngleBetweenMedians
def validate(password,to_register):
    mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
    order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    password=password.lower()

    a = 0
    b = 7
    #G1
    x0 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    y0 = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    G1=[55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424]
    #G2
    G2=[123,98]
    #G3
    x01=2
    y01=24
    G3=[2,24]
    #G4
    G4=[540,240]





    print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("initial configuration")
    print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("Curve: y^2 = x^3 + ",a,"*x + ",b, " mod ", mod," , #F(",mod,") = ", order)
    print("Base point: (",x0,", ",y0,")")
    #print("modulo: ", mod)
    #print("order of group: ", order)
    print()

    
        
        # print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
        # print("Elliptic Curve Diffie Hellman Key Exchange")
        # print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    x1= 2010000000000017
    G1X1, G1Y1 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x1, a, b, mod)
        # print("Server 1 public key: (",G1X1,", ", G1Y1,")")

    x2 = 2010000000000061
    G1X2, G1Y2 = EccCore.applyDoubleAndAddMethod(G1[0], G1[1], x2, a, b, mod)
        # print("Server 2 public key: (",G1X2,", ", G1Y2,")")
        
        # print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

        # aliceSharedX, aliceSharedY = EccCore.applyDoubleAndAddMethod(bobPublicX, bobPublicY, alicePrivate, a, b, mod)
        # print("alice shared key: (",aliceSharedX,", ", aliceSharedY,")")

        # bobSharedX, bobSharedY = EccCore.applyDoubleAndAddMethod(alicePublicX, alicePublicY, bobPrivate, a, b, mod)
        # print("bob shared key: (",bobSharedX,", ", bobSharedY,")")
    #--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    #G3
    x01=2
    y01=24
    def get_area(x,y):
        area=0.5*( (x[0]*(y[1]-y[2])) + (x[1]*(y[2]-y[0])) + (x[2]*(y[0]-y[1])) )
        return int(area)
    def getcofactor(m, i, j):
        return [row[: j] + row[j+1:] for row in (m[: i] + m[i+1:])]
    
    # defining the function to
    # calculate determinant value
    # of given matrix a.
    
    
    def determinantOfMatrix(mat):
    
        # if given matrix is of order
        # 2*2 then simply return det
        # value by cross multiplying
        # elements of matrix.
        if(len(mat) == 2):
            value = mat[0][0] * mat[1][1] - mat[1][0] * mat[0][1]
            return value
    
        # initialize Sum to zero
        Sum = 0
    
        # loop to traverse each column
        # of matrix a.
        for current_column in range(len(mat)):
    
            # calculating the sign corresponding
            # to co-factor of that sub matrix.
            sign = (-1) ** (current_column)
    
            # calling the function recursily to
            # get determinant value of
            # sub matrix obtained.
            sub_det = determinantOfMatrix(getcofactor(mat, 0, current_column))
    
            # adding the calculated determinant
            # value of particular column
            # matrix to total Sum.
            Sum += (sign * mat[0][current_column] * sub_det)
    
        # returning the final Sum
        return Sum
    def change_to_be_hex(s):
        return int(s,base=16)
        
    def xor_two_str(str1,str2):
        a = change_to_be_hex(str1)
        b = change_to_be_hex(str2)
        return hex(a ^ b)
    print('Password: ',password)
    p=0
    for character in password:
        p=p+(ord(character))
    #print(p)
    hash_password= hashlib.sha512(password.encode())
    hash_password=(hash_password).hexdigest()
    #print((hash_password))
    int_b1=random.getrandbits(512) 
    b1=hex(int_b1)
    b1=b1[2:]
    b2=xor_two_str(b1,hash_password)
    print('B2:-')
    print(b2)
    a1=random.getrandbits(512)
    a2=random.getrandbits(512)
    #print(a1)
    #print(a2)
    print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    G3X1,G3Y1=EccCore.applyDoubleAndAddMethod(x01, y01, p, a, b, mod)
    # G4X1,G4Y1=EccCore.pointAddition(540, 424, G3X1, G3Y1, a, b, mod)
    # x=[]
    # y=[]
    # z=[]
    # st1=str(G4X1)
    # st2=str(G4Y1)
    # st3=str(G4X1+G4Y1)
    # x.append(int(st1[0:28]))
    # x.append(int(st1[28:55]))
    # x.append(int(st1[55:]))
    # y.append(int(st2[0:28]))
    # y.append(int(st2[28:55]))
    # y.append(int(st2[55:]))
    # z.append(int(st3[0:28]))
    # z.append(int(st3[28:55]))
    # z.append(int(st3[55:]))

    # # x_half=G3X1//9
    # # x.append(x_half)
    # # x.append(x_half*7)
    # # x.append(x_half*2)
    # # y_half=G3Y1//9
    # # y.append(y_half*3)
    # # y.append(y_half*4)
    # # y.append(y_half*2)
    # # z_half=(G3X1+G3Y1)//9
    # # z.append(z_half*1)
    # # z.append(z_half*2)
    # # z.append(z_half*6)
    # A=[]
    # B=[]
    # C=[]
    # A.append(x[0])
    # A.append(y[0])
    # A.append(z[0])

    # B.append(x[1])
    # B.append(y[1])
    # B.append(z[1])

    # C.append(x[2])
    # C.append(y[2])
    # C.append(z[2])

    # D=[]
    # # print(x[0],x[1],x[2])
    # # D_x=(x[0]+x[1]+x[2])//3
    # # D_y=(y[0]+y[1]+y[2])//3
    # # D_z=(z[0]+z[1]+z[2])//3

    # # D.append(D_x)
    # # D.append(D_y)
    # # D.append(D_z)

    # A=np.array(A)
    # B=np.array(B)
    # C=np.array(C)
    # D.append((A[0]+B[0]+C[0])//3)
    # D.append((A[1]+B[1]+C[1])//3)
    # D.append((A[2]+B[2]+C[2])//3)
    # D=np.array(D)
    # D/=3
    # # print(D)
    # tmp_1=B-A
    # tmp_2=C-A
    # tmp_1=np.array(tmp_1)
    # tmp_2=np.array(tmp_2)
    # # print(tmp_1*tmp_2)
    # square = np.square(tmp_1 -tmp_2)
    # # Get the sum of the square
    # sum_square = np.sum(square)
    # distance = (sum_square)**0.5
    # # print('Distance-->',distance)

    # distance=distance*(2/3)**(0.5)
    # # D+=distance
    # D+=distance

    # t=[]
    # print("Points of the Tetrahedron: -")
    # print('Point A:(',end=" ")
    # print(A[0],',',A[1],' ,',A[2],')')
    # print('Point B:(',end=" ")
    # print(B[0],',',B[1],' ,',B[2],')')
    # print('Point C:(',end=" ")
    # print(C[0],',',C[1],' ,',C[2],')')
    # print('Point D:(',end=" ")
    # print(D[0],',',D[1],' ,',D[2],')')
    # # print(D_x)
    # # print(D_y)
    # # print(D_z)
    # # # print("\n")
    # print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    # for i in range(0,3):
    #     t.append(abs(A[i]-D[i]))
        

    # u=[]
    # for i in range(0,3):
    #     u.append(abs(B[i]-D[i]))
        
    # v=[]
    # for i in range(0,3):
    #     v.append(abs(C[i]-D[i]))
        

    # circumcenter=D
    # n_array = []
    # n_array.append(t)
    # n_array.append(u)
    # n_array.append(v)

    # dist_t=0
    # for i in range(len(D)):
    #     dist_t+=(abs(A[i]-D[i]))

    # dist_u=0
    # for i in range(len(D)):
    #     dist_u+=(abs(B[i]-D[i]))

    # dist_v=0
    # for i in range(len(D)):
    #     dist_v+=(abs(C[i]-D[i]))




    # deter=determinantOfMatrix(n_array)
    # # print(D[0])
    # # print(D[1])
    # # print(D[2])
    # # for r in n_array:
    # #    for c in r:
    # #       print(c,end = " ")
    # #    print()
    # u=np.array(u)
    # v=np.array(v)
    # t=np.array(t)
    # temp_u=np.array(u)
    # temp_v=np.array(v)
    # temp_t=np.array(t)
    # for i in temp_t:
    #     temp_t*=(dist_v**2)
    # temp_t*=u

    # for i in temp_u:
    #     temp_u*=(dist_t**2)
    # temp_u*=v
    # for i in temp_v:
    #     temp_v*=(dist_u**2)
    # temp_v*=t
    # # temp_u*=(dist_t**2)
    # # temp_u*=v
    # # temp_t*=(dist_v**2)
    # # temp_t*=u
    # # temp_v*=(dist_u**2)
    # # temp_v*=t

    # # print(temp_t[0],' ',temp_t[1],' ',temp_t[2])
    # temp=temp_t+temp_u+temp_v
    # temp/=(2*deter)
    # # print(temp[0])
    # # print(temp[1])
    # # print(temp[2])
    # circumcenter=np.array(circumcenter)
    # circumcenter+=temp
    
    # print('Circumcenter:(',end=" ")
    # print(circumcenter[0],',',circumcenter[1],' ,',circumcenter[2],')')
    # addCircumcentreinServer(circumcenter)
    # ComputeCircumcenter(G3X1,G3Y1)
    # ComputeAngleBetweenMedians(G3X1,G3Y1)
    # #--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # A,B C,D
    # A,C B,D
    # A,D B,C
    

    # angle1=angle(A,B,C,D)
    # angle2=angle(A,C,B,D)
    # angle3=angle(A,D,B,C)
    G2=[123,98]
    G2X1,G2Y1=EccCore.applyDoubleAndAddMethod(G2[0],G2[1],p,a,b,mod)
    # print('Angle in Radians:',(angle1+angle2+angle3)//3)
    # addAngleinServer((angle1+angle2+angle3)//3)
    print('Server 1:-')
    M1=[40,24]
    M2=[4,9]
    A2=list(EccCore.applyDoubleAndAddMethod(x0, y0, a2, a, b, mod))
    M1=np.array(M1)
    # print(A2)
    M2=np.array(M2)
    B2=M1+(a2*G1Y2)
    A1=list(EccCore.applyDoubleAndAddMethod(x0, y0, a1, a, b, mod))
    B1=M2+(a1*G1Y1)
    print('A2:')
    print(A2)
    print('B2:')
    print(B2)
    print('x1:',x1)
    print('a1:',a1)
    print('b1:',b1)
    print()
    print('Server 2:-')
    print('A1:')
    print(A1)
    print('B1:')
    print(B1)
    print('x2:',x2)
    print('a2:',a2)
    print('b2:',b2)
    print()
    
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    print("\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    # if(circumcenter[0]==4.351213441736146e+140 and circumcenter[1]==4.320647556048162e+140 and circumcenter[2]==1.3558284269041456e+140):
    #     return True
    # else:
    #     return False
    
    #print(B1)
    if(to_register):
        ComputeCircumcenter(G3X1,G3Y1,to_register)
        ComputeAngleBetweenMedians(G3X1,G3Y1,to_register)
        return True
    return (ComputeCircumcenter(G3X1,G3Y1,to_register) and ComputeAngleBetweenMedians(G3X1,G3Y1,to_register))


#print(validate("hi alexa",False))