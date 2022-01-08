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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode
from os.path import exists

version = 'v1.0'
preference = {"salt": b64encode(os.urandom(16)).decode('utf-8')}

def initialize():
    global preference, database

    preference['key'] = getKey('password').decode()

    if not(exists('database.en')):
        print('')

    database = open('database.en','w+')

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
    print('Password Manager')

def entryPoint():
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
            message = input('Message: ')
            password = getpass.getpass("Password: ")
            print(encrypt(message, password))
        elif(response == 'decrypt'):
            message = input('Fernet: ')
            password = getpass.getpass("Password: ")
            print(decrypt(message, password))
        elif(response == 'validate'):
            password = getpass.getpass("Password: ")
            checkPassword(password)
        else:
            print('Unknown Command')

def encrypt(message, password):
    return getFernet(password).encrypt(message.encode()).decode()

def decrypt(message, password):
    return getFernet(password).decrypt(message.encode()).decode()

def getKey(password):
    global preference
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(preference['salt'], 'utf-8'),
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def getFernet(password):
    key = getKey(password)
    return Fernet(key)

def checkPassword(password):
    return getKey(password).decode() == preference['key']

initialize()
entryPoint()