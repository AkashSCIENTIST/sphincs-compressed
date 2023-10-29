import cv2
import face_recognition
import os
import numpy as np
import datetime
import pickle
import datetime
import hashlib
import json
from sibc.sidh import SIKE, default_parameters
import time
import speech_recognition as sr
import pyttsx3
import datetime
import wikipedia
import webbrowser
import os
import time
import subprocess
from ecapture import ecapture as ec
import wolframalpha
import json
import requests

import hashlib
import random
import numpy as np
import math
import sys
from bson import json_util
applyKeyExchange = True
sys.path.insert(0,'crypto/python')
import sys
sys.path.insert(0,'sibc')
from Server2 import digitalSignature,add_block
from pymongo import MongoClient
from crypto.python.EccApp import validate
from crypto.python import EccCore
import base64
from package.sphincsc import SphincsC


sphincs = SphincsC()
sphincs.set_n(16)
sphincs.set_h(63)
sphincs.set_d(21)
sphincs.set_k(19)
sphincs.set_w(16)










#from server1.server1_app import views
#from crypto.python import EccApp

def scale(OldValue):
    OldMin=0
    OldMax=2147483647
    NewMax=21000
    NewMin=0
    OldRange = (OldMax - OldMin)  
    NewRange = (NewMax - NewMin)  
    NewValue = (((OldValue - OldMin) * NewRange) / OldRange) + NewMin
    return NewValue

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(proof=1,value=[], previous_hash='0',gas_value=0)

    def create_block(self, proof, value, previous_hash,gas_value):
        if(len(value)==None):
            block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'value':-1,
                 'gas_value':0
                 }
        else:    
            block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'value':value,
                 'gas_value':gas_value
                 }
        print(block)
        client = MongoClient("mongodb+srv://Cluster73137:S3PNMwUmMaAQpzPI@cluster73137.l29srvj.mongodb.net/")
        db=client.VoiceAssistant
        
        Blockchain= db.Blockchain
        block['index']=str(block['index'])
        block['timestamp']=str(block['timestamp'])
        block['proof']=str(block['proof'])
        block['previous_hash']=str(block['previous_hash'])
        block['value']=str(block['value'])
        result=Blockchain.insert_one(block)
        add_block(block)
        self.chain.append(block)
        return block

    def print_previous_block(self):
        if len(self.chain)==0:
            return -1
        return self.chain[-1]['previous_hash']
    def get_previous_block(self):
        return self.chain[-1]
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof ** 2 - int(previous_proof) ** 2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        encoded_block = json_util.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()

            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1

        return True

# sike = SIKE(**default_parameters)
def compare(value):
    sk, pk = sphincs.generate_key_pair()
    return digitalSignature([sk,pk],value,sphincs)
    
# class Transaction:
#     def __init__(self):
#         self.private_key, self.public_key = sphincs.spx_keygen()
        
#     def cmp1(self):
#         c, K = sike.Encaps(self.public_key)
#         K_ = sike.Decaps((self.s, self.private_key, self.public_key), c)
#         return K==K_
    

#     def signVerification(self):
#         if(self.cmp1()):
#             return True
#         else:
#             return False
def decode():
    rootdir = r'./Binary'
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            itr = open(os.path.join(subdir, file), 'rb')
            byte = itr.read()
            itr.close()

            value=r"./dataset2/"
            value+=file[:-4]
            value+=".jpg"
            decodeit = open(value, 'wb')
            decodeit.write(base64.b64decode((byte)))
            decodeit.close()


blockchain = Blockchain()
# tran = Transaction()
# Mining a new block
def mine_block(value,gas):
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    previous_block=previous_hash
    block = blockchain.create_block(proof,value, previous_hash,gas)
    
def addblock(value,gas):
    if(compare(value)):
        if(blockchain.print_previous_block()==-1):
            blockchain.create_block(1,value,'0',0)
        else:
            mine_block(value,scale(gas))
    else:
        print("Valid Key is required")

# #---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def facerecog():
    # decode()
    path = 'dataset2'
    images = []
    classNames = []
    mylist = os.listdir(path)
    for cl in mylist:
        curImg = cv2.imread(f'{path}/{cl}')
        images.append(curImg)
        classNames.append(os.path.splitext(cl)[0])

    def findEncodings(images):
        encodeList = []
        for img in images:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            encoded_face = face_recognition.face_encodings(img)[0]
            encodeList.append(encoded_face)
        return encodeList
    encoded_face_train = findEncodings(images)
    nameList = []
    
    def markAttendance(name):
        with open('Attendance.csv','r+') as f:
            myDataList = f.readlines()
            
            for line in myDataList:
                entry = line.split(',')
                nameList.append(entry[0])
            if name=="UnkNown":
                now = datetime.datetime.now()
                time = now.strftime('%I:%M:%S:%p')
                date = now.strftime('%d-%B-%Y')
                f.writelines(f'\n{name}, {time}, {date}')
            elif name not in nameList:
                now = datetime.datetime.now()
                time = now.strftime('%I:%M:%S:%p')
                date = now.strftime('%d-%B-%Y')
                f.writelines(f'\n{name}, {time}, {date}')

    cap  = cv2.VideoCapture(0)
    while True:
        success, img = cap.read()
        imgS = cv2.resize(img, (0,0), None, 0.25,0.25)
        imgS = cv2.cvtColor(imgS, cv2.COLOR_BGR2RGB)
        faces_in_frame = face_recognition.face_locations(imgS)
        encoded_faces = face_recognition.face_encodings(imgS, faces_in_frame)
        for encode_face, faceloc in zip(encoded_faces,faces_in_frame):
            matches = face_recognition.compare_faces(encoded_face_train, encode_face)
            faceDist = face_recognition.face_distance(encoded_face_train, encode_face)
            matchIndex = np.argmin(faceDist)
            # print(matchIndex)
            if matches[matchIndex]:
                name = classNames[matchIndex].upper().lower()
                y1,x2,y2,x1 = faceloc
                # since we scaled down by 4 times
                y1, x2,y2,x1 = y1*4,x2*4,y2*4,x1*4
                cv2.rectangle(img,(x1,y1),(x2,y2),(0,255,0),2)
                cv2.rectangle(img, (x1,y2-35),(x2,y2), (0,255,0), cv2.FILLED)
                cv2.putText(img,name, (x1+6,y2-5), cv2.FONT_HERSHEY_COMPLEX,1,(255,255,255),2)
                markAttendance(name)
            else:
                markAttendance('UnkNown')
                # print(encode_face.type)
                # print(str(img))
                
                addblock(str(img),np.sum(img))
                # print(base64.b64encode(img))
        cv2.imshow('webcam', img)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            return True
            break
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------




# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
print('Loading your AI personal assistant - G One')

engine=pyttsx3.init()
voices=engine.getProperty('voices')
engine.setProperty('voice',voices[0].id)


def speak(text):
    engine.say(text)
    engine.runAndWait()

def wishMe():
    hour=datetime.datetime.now().hour
    if hour>=0 and hour<12:
        speak("Hello,Good Morning")
        print("Hello,Good Morning")
    elif hour>=12 and hour<18:
        speak("Hello,Good Afternoon")
        print("Hello,Good Afternoon")
    else:
        speak("Hello,Good Evening")
        print("Hello,Good Evening")

def takeCommand():
    r=sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        audio=r.listen(source)

        try:
            statement=r.recognize_google(audio,language='en-in')
            print(f"user said:{statement}\n")

        except Exception as e:
            speak("Pardon me, please say that again")
            return "None"
        return statement


# speak("Loading your AI personal assistant G-One")
# wishMe()
# speak("I'm G-One. your AI personal assistant ")
# speak("Speed One Tera Hertz; Memory One Zetta Byte")

def Register():
    while True:
        speak("Tell me how can I help you now? Say 'register' to register and 'hello' to login")
        statement = takeCommand().lower()

        if statement==0:
            continue
        if "register" in statement:
            flag=False
            while True:
                speak("Tell me the Password")
                stat=takeCommand().lower()
                if(stat==0):
                    continue
                else:
                    if(validate(stat,True)):
                        flag=True
                if(flag):
                    return True
                    break
        elif "hello" in statement:
            while True:
                speak("Tell me the Password")
                stat=takeCommand().lower()
                if(stat==0):
                    continue
                else:
                    return validate(stat,False)
if __name__=='__main__':
    # print(compare("No one knows the reason for all this, but it is probably quantum. - Pyramids, Terry Pratchett (1989)"))
    
    facerecog()
    if(Register()==False):
        speak("You are not a valid user")
    else:
        while True:
            speak("Tell me how can I help you now?")
            statement = takeCommand().lower()

            if statement==0:
                continue
            client = MongoClient("mongodb+srv://Cluster73137:S3PNMwUmMaAQpzPI@cluster73137.l29srvj.mongodb.net/")
            db=client.server1
            voiceDetails = {'command': statement,'time': str(datetime.datetime.now())}
            VoiceCommands= db.VoiceCommands
            result=VoiceCommands.insert_one(voiceDetails)
            if "good bye" in statement or "goodbye" in statement or "ok bye" in statement or "stop" in statement or "see you soon" in statement:
                speak('your personal assistant G-one is shutting down,Good bye')
                print('your personal assistant G-one is shutting down,Good bye')
                break



            if 'wikipedia' in statement:
                speak('Searching Wikipedia...')
                statement =statement.replace("wikipedia", "")
                results = wikipedia.summary(statement, sentences=3)
                speak("According to Wikipedia")
                print(results)
                speak(results)

            elif 'open youtube' in statement:
                webbrowser.open_new_tab("https://www.youtube.com")
                speak("youtube is open now")
                time.sleep(5)

            elif 'open google' in statement:
                webbrowser.open_new_tab("https://www.google.com")
                speak("Google chrome is open now")
                time.sleep(5)

            elif 'open gmail' in statement:
                webbrowser.open_new_tab("gmail.com")
                speak("Google Mail open now")
                time.sleep(5)

            elif "weather" in statement:
                api_key="8ef61edcf1c576d65d836254e11ea420"
                base_url="https://api.openweathermap.org/data/2.5/weather?"
                speak("whats the city name")
                city_name=takeCommand()
                complete_url=base_url+"appid="+api_key+"&q="+city_name
                response = requests.get(complete_url)
                x=response.json()
                if x["cod"]!="404":
                    y=x["main"]
                    current_temperature = y["temp"]
                    current_humidiy = y["humidity"]
                    z = x["weather"]
                    weather_description = z[0]["description"]
                    speak(" Temperature in kelvin unit is " +
                        str(current_temperature) +
                        "\n humidity in percentage is " +
                        str(current_humidiy) +
                        "\n description  " +
                        str(weather_description))
                    print(" Temperature in kelvin unit = " +
                        str(current_temperature) +
                        "\n humidity (in percentage) = " +
                        str(current_humidiy) +
                        "\n description = " +
                        str(weather_description))

                else:
                    speak(" City Not Found ")


            elif 'time' in statement:
                strTime=datetime.datetime.now().strftime("%H:%M:%S")
                speak(f"the time is {strTime}")

            elif 'who are you' in statement or 'what can you do' in statement:
                speak('I am G-one version 1 point O your persoanl assistant. I am programmed to minor tasks like'
                    'opening youtube,google chrome,gmail and stackoverflow ,predict time,take a photo,search wikipedia,predict weather' 
                    'in different cities , get top headline news from times of india and you can ask me computational or geographical questions too!')


            elif "who made you" in statement or "who created you" in statement or "who discovered you" in statement:
                speak("I was built by Mirthula")
                print("I was built by Mirthula")

            elif "open stackoverflow" in statement:
                webbrowser.open_new_tab("https://stackoverflow.com/login")
                speak("Here is stackoverflow")

            elif 'news' in statement:
                news = webbrowser.open_new_tab("https://timesofindia.indiatimes.com/home/headlines")
                speak('Here are some headlines from the Times of India,Happy reading')
                time.sleep(6)

            elif "camera" in statement or "take a photo" in statement:
                ec.capture(0,"robo camera","img.jpg")

            elif 'search'  in statement:
                statement = statement.replace("search", "")
                webbrowser.open_new_tab(statement)
                time.sleep(5)

            elif 'ask' in statement:
                speak('I can answer to computational and geographical questions and what question do you want to ask now')
                question=takeCommand()
                app_id="R2K75H-7ELALHR35X"
                client = wolframalpha.Client('R2K75H-7ELALHR35X')
                res = client.query(question)
                answer = next(res.results).text
                speak(answer)
                print(answer)


            elif "log off" in statement or "sign out" in statement:
                speak("Ok , your pc will log off in 10 sec make sure you exit from all applications")
                subprocess.call(["shutdown", "/l"])

            elif "start" in statement: 
                speak('Face Recognition has just begun')
                facerecog()
            


time.sleep(3)
# -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------





