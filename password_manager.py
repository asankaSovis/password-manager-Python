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
import random
import string
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode
from os.path import exists

version = 'v1.0'
preference = {'salt': b64encode(os.urandom(16)).decode('utf-8')}
database = {}

strVals = {
    'existing_username': 'Error: The username already exists in the database under this platform',
    'incorrect_password': 'Error: The password you entered is incorrect',
    'unknown_commands': 'Unknown Command',
    'invalid_new_password_args': 'Invalid arguements for new password',
    'about_string': 'Password Manager',
    'version_string': 'Password Manager <v>',
    'password_string': 'Password: ',
    'input_platform': 'Platform: ',
    'input_username': 'Username: ',
    'input_manual_password': 'Manual Password: ',
    'reenter_manual_password': 'Reenter Password: ',
    'invalid_platform_inputs': 'The username and password cannot be empty',
    'empty_password': 'The password cannot be empty',
    'password_mismatch': 'The two passwords you entered did not match. Please try again',
    'fatal_error': 'Fatal Error: <l> | <e>',
    'password_added_successfully': 'Password added successfully',
    'new_password_warning': 'Platform: <p> Username: <u>\nDo you wish to procees?Y/N,S to show password',
    'show_password': 'Password: <p>',
    'password_abort': 'User rejected to save password'
}

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
    print(strVals['about_string'])

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

def checkPassword():
    # Validates the password
    password = getpass.getpass(strVals['password_string'])
    correct = (getKey(password).decode() == preference['key'])

    if not(correct):
        print(strVals['incorrect_password'])

    return (correct, password)

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

def addPassword(passcode, platform, username, password):
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
        print(strVals['existing_username'])

    # print(database)
    # print('\n\n')

def manualPassword():
    password1 = getpass.getpass(strVals['input_manual_password'])
    if password1 == '':
        print(strVals['empty_password'])
        return (False, '')
    password2 = getpass.getpass(strVals['reenter_manual_password'])
    if password1 != password2:
        print(strVals['password_mismatch'])
        return (False, '')
    return (True, password1)

def randomPassword(length = 12, uppercase = True, numbers = True, specialChar = True):
    sourceStr = string.ascii_lowercase
    if uppercase:
        sourceStr += string.ascii_uppercase
    if numbers:
        sourceStr += string.digits
    if specialChar:
        sourceStr += string.punctuation

    while(len(sourceStr) < length):
        sourceStr = sourceStr * 2

    return("".join(random.sample(sourceStr, length)))

def entryPoint():
    # Entry point of the application
    while(True):
        response = input('>>> ').split(" ")
        args = []
        if len(response) > 0:
            args = response[1:]
        response = response[0]

        if(response == 'exit'):
            if database != '':
                database.close()
            quit()
        elif(response == 'about'):
            about()
        elif(response == 'version'):
            print(strVals['version_string'].replace('<v>', version))
        elif(response == 'encrypt'):
            password = checkPassword()
            if password[0]:
                message = input('Message: ')
                print(encrypt(message, password[1]))
        elif(response == 'decrypt'):
            password = checkPassword()
            if password[0]:
                message = input('Fernet: ')
                print(decrypt(message, password[1]))
        elif(response == 'validate'):
            print(checkPassword())
        elif(response == 'add'):
            newPassword(args)
        else:
            print(strVals['unknown_commands'])

####################################################
## Interface

def newPassword(args):
    passcode = checkPassword()
    manual = '-m' in args

    if passcode[0]:
        password = (False, '')
        if not(manual):
             # (length, uppercase, numbers, specialChar)
            if (len(args) > 0):
                try:
                    passwordParams = (int(args[0]), '-u' in args, '-n' in args, '-c' in args)
                    password = (True, randomPassword(passwordParams[0], passwordParams[1], passwordParams[2], passwordParams[3]))

                except Exception:
                    print(strVals['invalid_new_password_args'])
                    return False

        platform = input(strVals['input_platform'])
        username = input(strVals['input_username'])
        if ((platform == '') or (username == '')):
            print(strVals['invalid_platform_inputs'])
            return False
        password = manualPassword()
        if password[0]:
            try:
                warning = input(strVals['new_password_warning'].replace('<p>', platform).replace('<u>', username))
                while (not((warning == 'Y') or (warning == 'N'))):
                    if(warning == 'S'):
                        print(strVals['show_password'].replace('<p>', password[1]))
                    warning = input(strVals['new_password_warning'].replace('<p>', platform).replace('<u>', username))
                if (warning == 'Y'):
                    addPassword(passcode[1], platform, username, password[1])
                    print(strVals['password_added_successfully'])
                else:
                    print(strVals['password_abort'])
                return True
            except Exception as err:
                print(strVals['fatal_error'].replace('<l>', 'addPassword').replace('<e>', err))
                return False
    return False
        
                    
                
                



####################################################
## Application

initialize()
# entryPoint()
# newPassword('password', 'facebook', 'asanka', 'hello')
# newPassword('password', 'facebook', 'akash', 'hello')
# print(getPlatform('password', 'facebook'))
# print('\n\n')
print(getUserInformation('password', 'A', 'B'))
#print(newPassword([]))