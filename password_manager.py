################################################
## 
## This is a basic password manager made in python
## Project start: 08/01/2022 6:00am
################################################

import json
import base64
import hashlib
import os
import getpass
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode
from os.path import exists

version = 'v1.0'
preference = {"salt": b64encode(os.urandom(16)).decode('utf-8')}
database = {}

def initialize():
    # Initializes the application
    # Loads preference data and the database
    global preference, database

    preference['key'] = getKey('password').decode()

    if not(exists('database.en')):
        print('')

    databaseFile = open('database.en','r')

    if not(databaseFile.read() == ''):
        databaseFile = open('database.en','r')
        database = json.loads(databaseFile.read())

    if not(exists('preferences.en')):
        print('')
    
    preferenceFile = open('preferences.en','r')

    if preferenceFile.readline() == '':
        preferenceFile = open('preferences.en','w+')
        preferenceFile.write(json.dumps(preference))
    else:
        preferenceFile = open('preferences.en','r')
        preference = json.loads(preferenceFile.read())


def about():
    # Show about data
    print('Password Manager')

def entryPoint():
    # Entry point of the application
    while(True):
        response = input('>>> ')
        if(response == 'exit'):
            if database != '':
                database.close()
            quit()
        elif(response == 'about'):
            about()
        elif(response == 'version'):
            print('Password Manager ' + version)
        elif(response == 'encrypt'):
            password = getpass.getpass("Password: ")
            if checkPassword(password):
                message = input('Message: ')
                print(encrypt(message, password))
            else:
                print('Error: The password you entered is incorrect')
        elif(response == 'decrypt'):
            password = getpass.getpass("Password: ")
            if checkPassword(password):
                message = input('Fernet: ')
                print(decrypt(message, password))
            else:
                print('Error: The password you entered is incorrect')
        elif(response == 'validate'):
            password = getpass.getpass("Password: ")
            checkPassword(password)
        elif(response == 'add'):
            print('')
        else:
            print('Unknown Command')

def encrypt(message, password):
    # Encrypts data
    return getFernet(password).encrypt(message.encode()).decode()

def decrypt(message, password):
    # Decrypts data
    return getFernet(password).decrypt(message.encode()).decode()

def getKey(password):
    # Gets the key from a given salt and password
    global preference
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(preference['salt'], 'utf-8'),
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def getFernet(password):
    # Gets the fernet
    key = getKey(password)
    return Fernet(key)

def checkPassword(password):
    # Validates the password
    return getKey(password).decode() == preference['key']

def getEncPlatformNames(password, platform):
    platformData = []

    for item in database.keys():
        if decrypt(item, password) == platform:
            platformData.append(item)
    
    return platformData

def getPlatform(password, platform):
    platformData = []

    for item in database.keys():
        if decrypt(item, password) == platform:
            platformData = platformData + database[item]
    
    return platformData

def getUserData(password, platform, username):
    platformData = getPlatform(password, platform)
    userData = []

    for dict in platformData:
        for item in dict.keys():
            if decrypt(item, password + platform) == username:
                userData.append(tuple(dict[item]))

    return userData

def decryptItem(data, password, platform, username):
    decryptedList = []
    for item in data:
        decryptedList.append(decrypt(item, password + platform + username))
    return tuple(decryptedList)

def getUserInformation(password, platform, username):
    userData = getUserData(password, platform, username)
    decUserData = []

    for item in userData:
        decUserData.append(decryptItem(item, password, platform, username))

    return decUserData

def newPassword(passcode, platform, username, password):
    # Adds new information to the database
    time = datetime.now()
    encPlatform = encrypt(platform, passcode)
    encUsername = encrypt(username, passcode + platform)
    encPassword = encrypt(password, passcode + platform + username)
    enctime = encrypt(time.strftime("%Y-%m-%d %H:%M:%S"), passcode + platform + username)

    profile = {encUsername : (encPassword, enctime)}

    platformInstances = getEncPlatformNames(passcode, platform)

    if len(getUserData(passcode, platform, username)) == 0:
        if len(platformInstances) == 0:
            database[encPlatform] = [profile]
        else:
            print(platformInstances[0])
            database[platformInstances[0]].append(profile)

        databaseFile = open('database.en','w+')
        databaseFile.write(json.dumps(database))
    else:
        print('Error: The username already exists in the database under this platform')

    # print(database)
    # print('\n\n')

def randomPassword(length = 12, uppercase = True, numbers = True, punctuation = True, specialChar = True):
    password = ''
    #while len(password) < length:
    for i in range(20):
        key = Fernet.generate_key()
        f = Fernet(key)
        #password = f.encrypt(b64encode(os.urandom(16))).decode()
        password = os.urandom(16)
        print(key)


####################################################
## Application

#initialize()
# entryPoint()
# newPassword('password', 'facebook', 'asanka', 'hello')
# newPassword('password', 'facebook', 'akash', 'hello')
# print(getPlatform('password', 'facebook'))
# print('\n\n')
# print(getUserInformation('password', 'facebook', 'asanka'))
randomPassword()