###############################################################################
##                            %% 🔐 PASSWORD MANAGER 🔐 %%
##                                  © Asanka Sovis
##
##                   This is a basic password manager made in python.
##                                       NOTE:
##                   This is still under development and must not be
##                          used as primary password manager.
##                            *Made with ❤️ in Sri Lanka
##
##     - Author: Asanka Sovis
##     - Project start: 08/01/2022 6:00am
##     - Version: 0
##     - License: MIT Open License
###############################################################################

import json # Handle JSON format
import base64 # Handle base64 conversions
import os # Access OS functions
import getpass # Input passwords
import random # Generate random data
import string # Use string commands
from datetime import datetime # Use date and time

# Fernet encryption module
# NOTE: Cryptography is NOT an included library. It needs to be installed
#       by pip install cryptography
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError or ModuleNotFoundError:
    print('Cryptography module does not exist. This is an important module. Please install it by using the "pip install cryptography" command')
    exit(1)

# Pyperclip clipboard module
# NOTE: Pyperclip is NOT an included library. It needs to be installed
#       by pip install pyperclip
try:
    import pyperclip as pc
except ImportError or ModuleNotFoundError:
    print('Pyperclip module does not exist. Please install it by using the "pip install pyperclip" command.'\
        'You can still use the application; but will get an error if you try to use the "copy" command.')
    exit(1)

from base64 import b64encode # Loading only the base64 encoding function
from os.path import exists # Used to check if files exist

####################################################
##### GLOBAL VARIABLES

version = 'v0' # Version number of the application. Set accordingly
preference = {'salt': b64encode(os.urandom(16)).decode('utf-8')} # A salt is generated in case
database = {} # This is the database used in the application

strVals = {
    # This database hold all the strings used in messages and inputs throughouts the application
    # These can later be set to load from a text file for ease
    'loading_information': '------------------------------------------\n**Password Manager**\n------------------------------------------\n',
    'initializing_application': 'Initializing application...',
    'no_database_found': 'No database found. Creating database...',
    'initializing_preferences': 'Loading preferences...\n',
    'ready': 'Ready',
    'existing_username': 'Error: The username already exists in the database under this platform',
    'incorrect_password': 'Error: The password you entered is incorrect',
    'unknown_commands': 'Unknown Command',
    'invalid_new_password_args': 'Invalid arguements for new password',
    'invalid_edit_password_args': 'Invalid arguements for edit password',
    'invalid_view_password_args': 'Invalid arguements for accessing password',
    'invalid_delete_password_args': 'Invalid arguements for deleting password',
    'invalid_search_args': 'Invalid arguements for search provided',
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
    'password_changed_successfully': 'Password changed successfully',
    'password_deleted_successfully': 'Profile deleted successfully',
    'show_username_platform': '\nPlatform: <p> | Username: <u>\n',
    'edit_password_warning': 'WARNING: The password will be PERMANENTLY changed in the following Profile',
    'delete_password_warning': 'WARNING: The following Profile will be deleted PERMANENTLY',
    'proceed_warning_question': 'Do you wish to proceed?Y/N ',
    'proceed_warning_question_with_show': 'Do you wish to proceed?Y/N,S to show password ',
    'show_password': '\nPassword: <p>\n',
    'show_password_with_info': 'Password: <p>           | Added Date: <d>',
    'user_abort': 'User rejected the operation',
    'copy_error': 'An error occured when attempting to copy the data. Maybe the Pyperclip module is not installed',
    'duplicate_user_platform': 'The same user exist in the platform',
    'no_user_platform': 'This user is not under this platform',
    'non_existent_platform': 'The platform does not exist',
    'non_existent_username': 'THe username does not exist under the platform',
    'same_password_to_edit': 'The password you entered is the same as the existing password. Modification did not take place',
    'user_or_platform_not_exist': 'The user and/or platform does not exist',
    'password_copied_successfully': 'The password was copied successfully!',
    'show_all_platforms': 'Showing all platforms in the database----------------------\n',
    'show_keyword_platforms': 'Showing all platforms that match "<k>"---------------------\n',
    'show_all_usernames': 'Showing all usernames in the database----------------------\n',
    'show_all_usernames_in_keyword_platforms': 'Showing all usernames in "<p>"--------------\n',
    'show_keyword_usernames': 'Showing all usernames that match "<k>"----------------\n',
    'show_keyword_usernames_in_keyword_platforms': 'Showing usernames that match "<k>" in "<p>"--------------\n',
}

####################################################
##### INITIALIZATION FUNCTION

def initialize():
    # INITIALIZES THE APPLICATION
    # This includes loading preference data and the database
    # Accepts none / Returns null
    global preference, database

    print(strVals['initializing_application'])

    if not(exists('database.en')):
        # If the database doesn't exist, ask user if they like to load an existing database
        # NOTE: For now it's not doing anything. Can activate if needed
        print(strVals['no_database_found'])

    databaseFile = open('database.en','r')
    # Opens the database 01. to create an empty database if one doesn't exist, 02. to check if it's empty

    if databaseFile.read() != '':
        # If the database is not empty we read the database and dump the contents to our dictionary
        databaseFile = open('database.en','r')

        try:
            database = json.loads(databaseFile.read())
            
        except Exception as err:
            print(strVals['fatal_error'].replace('<l>', 'Database loading').replace('<e>', err))
            exit()

    # if not(exists('preferences.en')):
        # If the preferences file doesn't exist, we can use this section to do something
        # NOTE: For now it's not doing anything. Can activate if needed
    #     print('')
    
    print(strVals['initializing_preferences'])

    preferenceFile = open('preferences.en','r')
    # Opens the preference file 01. to create an empty file if one doesn't exist, 02. to check if it's empty

    try:
        if preferenceFile.read() == '':
            # If the preference file is empty we:
            #       01. Generate a new key from a new password and store it on the preference dictionary
            #       02. Open the preference file to create one if needed
            #       03. Dump preference data to this file
            # NOTE: A default random salt is generated at the start of the application
            # NOTE: If the preference file is empty, we must ask the user to create a new password
            #       and this password MUST be the one used to generate the key. Implement this
            #       functionality!
            preference['key'] = getKey('password').decode()
            preferenceFile = open('preferences.en','w+')
            preferenceFile.write(json.dumps(preference))

        else:
            # If the preference file is not empty we dump all content to the preference dictionary
            preferenceFile = open('preferences.en','r')
            preference = json.loads(preferenceFile.read())
    
    except Exception as err:
        print(strVals['fatal_error'].replace('<l>', 'Preferences loading').replace('<e>', err))
        exit()

####################################################
##### CRYPTOGRAPHIC FUNCTIONS

def encrypt(message, password):
    # ENCRYPTING DATA
    # This function handles the encrypting of data. It accesses the getFernet() function with provided password to get
    # the encryption module and uses it to encrypt any arbitrary message sent for encrypting
    # Accepts the message as String, password as String / Returns the encrypted data as base64 encoded String

    try:
        return getFernet(password).encrypt(message.encode()).decode()
            
    except Exception as err:
        print(strVals['fatal_error'].replace('<l>', 'encrypt()').replace('<e>', err))
        exit()

def decrypt(message, password):
    # DECRYPTING DATA
    # This function handles the decrypting of data. It accesses the getFernet() function with provided password to get
    # the encryption module and uses it to decrypt any fernet encrypted message sent for decrypting
    # Accepts the encoded message as String, password as String / Returns the decrypted data as String
    # NOTE: Implement error handling!
    return getFernet(password).decrypt(message.encode()).decode()

def getKey(password):
    # GENERATES A KEY FROM PASSWORD
    # This function generates a key from a given password
    # The keys are according to Fernet specs https://github.com/fernet/spec/blob/master/Spec.md
    # Key Format : Signing-key (128 bit) ‖ Encryption-key (128 bit)
    # Accepts password as String / Return Fernet key as base64 encoded String

    global preference

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = bytes(preference['salt'], 'utf-8'),
        iterations = 390000,
    )

    try:
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
    except Exception as err:
        print(strVals['fatal_error'].replace('<l>', 'getKey()').replace('<e>', err))
        exit()

def getFernet(password):
    # GET THE FERNET
    # This function generates a Fernet module from a given password. It access the getKey() function to
    # get a Fernet key which is used to generate and return a Fernet
    # Accepts password as String / Returns the Fernet as module

    key = getKey(password)

    try:
        return Fernet(key)
            
    except Exception as err:
        print(strVals['fatal_error'].replace('<l>', 'getFernet()').replace('<e>', err))
        exit()

####################################################
##### GENERAL FUNCTIONS

def checkPassword():
    # VALIDATE A USER ENTERED PASSWORD
    # This function asks the user to enter their password and validate it using the stored hash of the
    # password. If it doesn't match, it notifies the user and returns the result
    # Accepts none / Returns tuple (whether validation was successful as Boolean[True-validated/False-Invalidated],
    #                       password as String)
    # NOTE: If the validation falied, the password in returned tuple is empty

    password = getpass.getpass(strVals['password_string']) # We use getpass instead of input for safety
    # NOTE: getpass hides the password while the user enteres it
    correct = (getKey(password).decode() == preference['key']) # Compare the stored key and hashed password to validate
    # if the user entered password is valid. This is stored in correct variable as boolean for reference

    if not(correct):
        # In case the password is invalid we show error message
        print(strVals['incorrect_password'])

    # Returning the results
    return (correct, password)

def getEncPlatformNames(password, platform):
    # GET THE **ENCRYPTED** PLATFORM NAMES FROM DATABASE
    # This function scans the database and retrievs the platforms from it
    # NOTE: These data are encrypted and thus the returned data is ENCRYPTED
    # NOTE: This only returns the list of encrypted platform names as String
    # NOTE: In theory, the platform name must appear only once in the database but still we do
    #       a looping check for added safety and retrieve every appearance from a loop
    # NOTE: This function can be used to validate if a platform already exists in the database
    # Accepts password as String, platform as String / Returns the retrieved data as list

    platformData = []

    for item in database.keys():
        # We first take out all the keys in the database[Platforms] and for each one, we decrypt
        # it using the password and compare it with the platform name sent for reference.
        # NOTE: The reason why we have to decrypt each item instead of encrypting the provided
        #       platform once and comparing it with the existing encrypted items, is because with
        #       Fernet encrypting, the resulting encrypting is different for the same item at different
        #       times
        if decrypt(item, password) == platform:
            platformData.append(item)
    
    return platformData

def getPlatform(password, platform):
    # GET THE DATA ASSOCIATED WITH A PLATFORM FROM DATABASE
    # This function scans the database and retrievs the platforms from it
    # Unlike the getEncPlatformNames() function, this returns a list of dictionaries that
    # Contain the data available under this platform. This include the usernames as keys
    # and the data of relevant user name as values of each key. Refer to the database structure
    # for more details. Of course this data is also encrypted
    # NOTE: In theory, the platform name must appear only once in the database but still we do
    #       a looping check for added safety and retrieve every appearance from a loop
    # NOTE: This function can be used to validate if a platform already exists in the database
    #       but still the getEncPlatformNames() is recommended for efficiency
    # Accepts password as String, platform as String / Returns the retrieved data as list

    platformData = []

    for item in database.keys():
        # We first take out all the keys in the database[Platforms] and for each one, we decrypt
        # it using the password and compare it with the platform name sent for reference.
        # NOTE: The reason why we have to decrypt each item instead of encrypting the provided
        #       platform once and comparing it with the existing encrypted items, is because with
        #       Fernet encrypting, the resulting encrypting is different for the same item at different
        #       times
        if decrypt(item, password) == platform:
            platformData = platformData + database[item]
    
    return platformData

def getUserData(password, platform, username):
    # EXTRACT USER DATA FROM PLATFORM
    # This function extracts the data (password, time, etc.) from the database for a given username
    # and platform. It uses the getPlatform() function to extract the data for a particular platform
    # and then use this data to extract the information for that particular username.
    # NOTE: The extracted data is still encrypted and in order to use it, it has to be decrypted
    # Accepts password as String, platform as String, username as String / Returns encrypted data
    #                   as list of tuples of user information
    #       [(encPassword for 1, encTime for 1), (encPassword for 2, encTime for 2), ...]

    platformData = getPlatform(password, platform)
    userData = []

    for dict in platformData:
        # For each username dictionary returned, we iterate through them and for each username
        # we decrypt it and compare it with the provided username. If they match, the values
        # (tuples with information) is added to a list which is returned back
        # NOTE: Since JSON Stores tuples as lists we also convert the list to tuple. This
        #       is not a must but is efficient as information stored is in a fixed structure
        for item in dict.keys():
            if decrypt(item, password + platform) == username:
                userData.append(tuple(dict[item]))

    return userData

def decryptItem(data, password, platform, username):
    # DECRYPT DATA
    # This function decrypts the data that is given to it using the password, platform and username
    # NOTE: Data is in tuple form. This is so that encrypted data retrieved from getUserData() function
    #       can be quickly decrypted and retrieved with ease
    # Accets data as a tuple of Strings (Lists is also acceptable but is not what is intended),
    #           password as String, platform as String, username as String / Returns the same
    #           data in the same structure but decrypted and as a tuple

    decryptedList = []

    for item in data:
        # We perform the decryption for each item in the tuple (or list) and add it to a temporary
        # list
        decryptedList.append(decrypt(item, password + platform + username))

    return tuple(decryptedList)

def getUserInformation(password, platform, username):
    # GETS USER INFORMATION
    # This function decrypts the data from getUserData() function using the decryptItem()
    # function. This function is useful to directly get the decrypted information of the user
    # without any steps, as this handles the in between step of decrypting each item in
    # the data
    # Accepts password as String, platform as String, username as String / Returns decrypted
    #       user information as list of tuples of user information
    #       [(password for 1, time for 1), (password for 2, time for 2), ...]

    userData = getUserData(password, platform, username)
    decUserData = []

    for item in userData:
        # For each item in user data we got from the getUserData() function, we decrypts them and
        # from the decryptItem() function and add the returned tuple to a list to be then returned
        # back
        decUserData.append(decryptItem(item, password, platform, username))

    return decUserData

def getUsernamesInPlatform(password, platform, username):
    # EXTRACT USERNAMES FROM PLATFORM
    # This function extracts the usernames from the database for a given username
    # and platform. It uses the getPlatform() function to extract the data for a particular platform
    # and then use this data to extract the name for that particular username.
    # Accepts password as String, platform as String, username as String / Returns usernames
    #       as list of Strings

    platformData = getPlatform(password, platform)
    userData = []

    for dict in platformData:
        # For each username dictionary returned, we iterate through them and for each username
        # we decrypt it and compare it with the provided username. If they match, the decrypted
        # username is added to a list which is returned back
        for item in dict.keys():
            extracts = decrypt(item, password + platform)
            if username in extracts:
                userData.append(extracts)

    return userData

def addPassword(passcode, platform, username, password):
    # ADDS NEW INFORMATION TO THE DATABASE
    # This function can be used to add an information set to the database. It will handle
    # the encryption of data, duplicates and writing to the database itself
    # Accepts passcode as String, platform as String, username as String, password as String /
    #           Return success as boolean
    # NOTE: In this function, the password is the password that the user needs to store
    #       not the password used to access the database. That is the passcode here

    time = datetime.now() # We also store the date and time for validating purposes

    # Below, all data is encrypted according to the method discussed. Refer to documentation
    # for more information
    encPlatform = encrypt(platform, passcode)
    encUsername = encrypt(username, passcode + platform)
    encPassword = encrypt(password, passcode + platform + username)
    enctime = encrypt(time.strftime("%Y-%m-%d %H:%M:%S"), passcode + platform + username)

    # A profile is created for that particular username as a dictionary that has the username
    # as the key and information in the tuple form
    profile = {encUsername : (encPassword, enctime)}

    # Here we check if the platform is already included in the database. We store all the
    # instances of this platform appearing in the database as a list using the getEncPlatformNames()
    # function.
    # NOTE: In theory, there should be only one instance but we still check for multiple just in case
    # NOTE: The reason why we do is so that we can store the new profile data under the same platform
    #       instead of creating new instance of this platform
    # NOTE: A platform can have multiple user profiles and multiple user profiles with the same username
    #       can be created under different platforms. However, same platform MUST NOT hold multiple
    #       profiles under the same username. Checks to mitigate this is taken here
    platformInstances = getEncPlatformNames(passcode, platform)

    if len(getUserData(passcode, platform, username)) == 0:
        # We first check if a user profile exist under the same username within this platform. This is
        # done by using the count of lists returned by the getUserData() function. If so, we throw an
        # error. Otherwise we check if the platform is a new platform. This is done by using the count
        # of platformInstances list. If so we use the encrypted platform name, or else we use the
        # first instance of platform name we get and discard the encrypted platform name we made before
        # Then we append the profile to the list
        if len(platformInstances) == 0:
            database[encPlatform] = [profile]
        else:
            # print(platformInstances[0])
            database[platformInstances[0]].append(profile)

        # Once updating the loaded database, we dump it back to the physical database to store
        dumpDatabase()

        return True

    else:
        print(strVals['existing_username'])

    return False
    # print(database)
    # print('\n\n')

def deletePassword(passcode, platform, username):
    # DELETES AN EXISTING PROFILE
    # This function will delete an existing profile from the database. This will go through the
    # database and delete all instances of the profile within the given platform.
    # Accepts passcode as String, platform as String, username as String / Return success as boolean

    # Here we check if the platform is already included in the database. We store all the
    # instances of this platform appearing in the database as a list using the getEncPlatformNames()
    # function.
    # NOTE: In theory, there should be only one instance but we still check for multiple just in case
    platformInstances = getEncPlatformNames(passcode, platform)

    if len(getUserData(passcode, platform, username)) != 0:
        # We first check if a user profile exist under the same username within this platform. This is
        # done by using the count of lists returned by the getUserData() function. If not, we throw an
        # error. Otherwise we check if the platform exist. This is done by using the count of
        # platformInstances list. If so we use the encrypted platform name to get all profiles under
        # it. Then for each list item, we iterate and check if the decrypted first key item (Because
        # the profile dictionaries have only a single key value pair) match with the username. If so
        # we delete that instance from the database
        if len(platformInstances) == 0:
            # Profile not exist
            print(strVals['non_existent_username'])

        else:
            # Found the profile in the right platform under right username!
            # print(platformInstances[0])
            for platformItem in platformInstances:
                usernameInstances = database[platformItem]

                for usernameInstance in usernameInstances:
                    if decrypt(list(usernameInstance.keys())[0], passcode + platform) == username:
                        database[platformItem].remove(usernameInstance)
                        dumpDatabase()

                        return True

        # Once updating the loaded database, we dump it back to the physical database to store
        dumpDatabase()

    else:
        # Platform not exist
        print(strVals['non_existent_platform'])
    return False

def editPassword(passcode, platform, username, password):
    # EDIT AN EXISTING PROFILE
    # This function will edit an existing profile from the database. This will go through the
    # database and edit all instances of the profile within the given platform.
    # Accepts passcode as String, platform as String, username as String, password as String / Return
    #           success as boolean

    # Here we check if the platform is already included in the database. We store all the
    # instances of this platform appearing in the database as a list using the getEncPlatformNames()
    # function.
    # NOTE: In theory, there should be only one instance but we still check for multiple just in case
    platformInstances = getEncPlatformNames(passcode, platform)

    if len(getUserData(passcode, platform, username)) != 0:
        # We first check if a user profile exist under the same username within this platform. This is
        # done by using the count of lists returned by the getUserData() function. If not, we throw an
        # error. Otherwise we check if the platform exist. This is done by using the count of
        # platformInstances list. If so we use the encrypted platform name to get all profiles under
        # it. Then for each list item, we iterate and check if the decrypted first key item (Because
        # the profile dictionaries have only a single key value pair) match with the username. If so
        # we edit that instance in the database itself to include the new password along with the current
        # time
        if len(platformInstances) == 0:
            # Profile not exist
            print(strVals['non_existent_username'])

        else:
            # Found the profile in the right platform under right username!
            # print(platformInstances[0])
            for platformItem in platformInstances:
                usernameInstances = database[platformItem]

                for i in range(len(usernameInstances)):
                    usernameInstance = list(usernameInstances[i].keys())[0]
                    
                    if decrypt(usernameInstance, passcode + platform) == username:
                        if decrypt(database[platformItem][i][usernameInstance][0], passcode + platform + username) != password:
                            time = datetime.now()
                            encPassword = encrypt(password, passcode + platform + username)
                            enctime = encrypt(time.strftime("%Y-%m-%d %H:%M:%S"), passcode + platform + username)

                            database[platformItem][i][usernameInstance] = (encPassword, enctime)
                            dumpDatabase()

                            return True

                        else:
                            print(strVals['same_password_to_edit'])

        # Once updating the loaded database, we dump it back to the physical database to store
        dumpDatabase()

    else:
        # Platform not exist
        print(strVals['non_existent_platform'])
    
    return False

def dumpDatabase():
    # DUMP DATA TO FILE
    # All updates to the database is dumped back to the physical file
    # Accepts none / Return null
    databaseFile = open('database.en','w+')
    databaseFile.write(json.dumps(database))

def getPlatformNames(password, keyword = ''):
    # GET THE **DECRYPTED** PLATFORM NAMES FROM DATABASE
    # This function scans the database and retrievs the platforms from it
    # NOTE: These data are decrypted and thus the returned data is NOT ENCRYPTED
    # NOTE: This only returns the list of decrypted platform names as String
    # NOTE: In theory, the platform name must appear only once in the database but still we do
    #       a looping check for added safety and retrieve every appearance from a loop
    # NOTE: This function can be used to validate if a platform already exists in the database
    # Accepts password as String, keyword as String / Returns the retrieved data as list

    platformData = []

    for item in database.keys():
        # We first take out all the keys in the database[Platforms] and for each one, we decrypt
        # it using the password and check if it exist in the list. If not we add it
        platform = decrypt(item, password)

        if not(platform in platformData) and (keyword in platform):
            platformData.append(platform)
    
    return platformData

def searchUsernames(password, keyword = '', platform = ''):
    # SEARCH USERNAME IN DATABASE
    # This function can search the database for a particular username or all and
    # return them back as a list of tuples with Platform and its corresponding
    # usernames.
    # Accept password as String, keyword as String(Default ''), platform as String(Default '') /
    # Return platforms as a list of tuples of the form
    # [(Platform 01, [Username 01, Username 02, ...]), (Platform 02, [Username 01, Username 02, ...]), ...]

    platforms = getPlatformNames(password, platform) # Get the list of platform names
    returnData = [] #List to be returned

    # We iterate through each platform and use getUsernamesInPlatform() to get the matching
    # usernames. If data is returned, we append them to the return variable in correct
    # form
    for item in platforms:
        matches = getUsernamesInPlatform(password, item, keyword)
        if platform in item:
            returnData.append((item, matches))

    return returnData

####################################################
###### PASSWORD HANDLING

def manualPassword():
    # CREATE A PASSWORD MANUALLY
    # This function is used if the user needs to create a password manually. This
    # handles all the inputs and messaging
    # Accepts none / Returns tuple of the form (success as Boolean, entered password as String)
    # NOTE: We ask user to enter the password twice in order to make sure no errors occur
    # NOTE: Success is true if the password entered is acceptable and false if not. Check below
    #       for how it is checked
    # NOTE: Password is returned only if successful, otherwise returned string is empty

    # In order to accept the password, it must not be empty and also both times the user
    # enters the password must match
    password1 = getpass.getpass(strVals['input_manual_password']) # First entry

    if password1 == '':
        # We first check if the password is empty. If so we throw an error and return fail
        print(strVals['empty_password'])
        return (False, '')

    password2 = getpass.getpass(strVals['reenter_manual_password']) # Second entry

    if password1 != password2:
        # Next we make sure both times the user entered the password, they match if not
        # we return an error and exit. Otherwise we return success and the password
        print(strVals['password_mismatch'])
        return (False, '')

    return (True, password1)

def randomPassword(length = 12, uppercase = True, numbers = True, specialChar = True):
    # GENERATE A PASSWORD AUTOMATICALLY
    # This function generates a password automatically at random for security
    # It uses a list of characters from eacj type of characters and uses the random module
    # to randomly assign to a string
    # Accepts length as int(Default 12), uppercase as Boolean(Default True), numbers as
    # Boolean(Default True), specialChar as Boolean(Default True) / Return password as String
    # These variables can be changed to customize the password style

    sourceStr = string.ascii_lowercase # Include lowercase in the charset
    # NOTE: Lowercase chars MUST be included

    if uppercase:
        # Include Uppercase in the charset
        sourceStr += string.ascii_uppercase
    if numbers:
        # Include Numbers in the charset
        sourceStr += string.digits
    if specialChar:
        # Include Special Characters and Punctuations in the charset
        sourceStr += string.punctuation

    while(len(sourceStr) < length):
        # Generates a charset bigger than the expected length of the password
        # This is done to mitigate issues where charset might be too small to
        # jumble into a password. random.sample() function assigns chars at
        # random and doesn't reuse the same character which means an error can
        # occur if the charset is smaller than the password.
        # NOTE: This is in generally not possible as lowercase is mandatory and
        # passwords are smaller than 26 however this put in place just in case
        sourceStr = sourceStr * 2

    return("".join(random.sample(sourceStr, length)))

####################################################
###### ENTRY POINT TO THE APPLICATION

def entryPoint():
    # MAIN FUNCTION THAT RUNS ON LAUNCH
    # This function runs in order to parse commands issued by the user
    # It will run until an error occur or user enter the exit command
    # Accepts none / Return null

    print(strVals['ready'])

    while(True):
        # Application loop
        response = input('>>> ').split(" ") # Parsing the response
        args = []

        if len(response) > 0:
            # Arguements passed are parsed and assigned to a variable as a list
            # of strings and the command is stored in the response variable as
            # a String
            args = response[1:]

        response = response[0]

        # This section parses the commands
        if(response == 'exit'):
            # Exit command. When given the application exits
            # >>> exit
            dumpDatabase()
            quit()

        elif(response == 'about'):
            # About command. Opens the about section of the application
            # >>> about
            showAbout()

        elif(response == 'version'):
            # Version command. Shows the version details of the application
            # >>> version
            showVersion()

        elif(response == 'encrypt'):
            # Encrypt command. Simply encrypts a provided string. Only
            # used for debug purposes
            # >>> encrypt
            password = checkPassword()

            if password[0]:
                message = input('Message: ')
                print(encrypt(message, password[1]))

        elif(response == 'decrypt'):
            # Decrypt command. Simply decrypts a provided string. Only
            # used for debug purposes
            # >>> decrypt
            password = checkPassword()

            if password[0]:
                message = input('Fernet: ')
                print(decrypt(message, password[1]))

        elif(response == 'validate'):
            # Validates the given password. Only used for debug purposes
            # >>> validate
            print(checkPassword())

        elif(response == 'add'):
            # Add command. Adds a new password to the database
            # >>> add           [Add password with default autogenerated password]
            # >>> add <size> <-u, -n, -c one or more>
            #                   [Add password with custom autogenerated password]
            # >>> add -m        [Add manual password]
            newProfile(args)

        elif(response == 'edit'):
            # Edit command. Edits an existing password in the database
            # >>> edit <platform> <username>
            #                   [Edit password with default autogenerated password]
            # >>> edit <platform> <username> <size> <-u, -n, -c one or more>
            #                   [Edit password with custom autogenerated password]
            # >>> edit <platform> <username> -m        [Edit manual password]
            editProfile(args)

        elif(response == 'delete'):
            # Delete command. Deletes an existing password in the database
            # >>> delete <platform> <username>
            deleteProfile(args)

        elif(response == 'show'):
            # Show command. Shows an existing password in the database
            # >>> show <platform> <username>
            showPassword(args)

        elif(response == 'copy'):
            # Copy command. Copies an existing password in the database
            # >>> copy <platform> <username>
            copyPassword(args)

        elif(response == 'platforms'):
            # Platforms command. Shows/search all platforms in database
            # >>> platform
            #                   [All the platforms]
            # >>> platform <keyword>
            #                   [Search platform with specific keyword]
            # >>> platform <keyword> <rows>
            #                   [Search platform with specific keyword and list results in specified row count]
            showPlatforms(args)

        elif(response == 'usernames'):
            # Usernames command. Shows/search all usernames in database
            # >>> usernames
            #                   [All the usernames in all platforms]
            # >>> usernames <keyword>
            #                   [Search usernames with specific keyword in all platforms]
            # >>> usernames <keyword> <platform>
            #                   [Search platform with specific keyword and platform]
            # >>> usernames -a <platform>
            #                   [All usernames in specified platform]
            # >>> usernames <keyword/'-a'> <platform> <rows>
            #                   [Search platform with specific keyword and platform and list results in specified row count]
            showUsernames(args)

        else:
            # If unknown command is issued, show error message
            print(strVals['unknown_commands'])

        print()

####################################################
###### INTERFACE FUNCTIONS

def showVersion():
    # SHOW VERSION DATA
    # This function shows the version of the application to the user
    # Accept none / Return null
    # NOTE: This section still needs improving!
    print(strVals['version_string'].replace('<v>', version))

def showAbout():
    # SHOW ABOUT DATA
    # This function is used to print about information to the user
    # Accepts none / Returns null
    # NOTE: This section still needs improving!
    print(strVals['about_string'])

def newProfile(args):
    # NEW PASSWORD FUNCTION
    # Handles the user side tasks to add a new password to the system. This will handle messages,
    # error checks, and inputs.
    # Accepts args as list of Strings / Return success as Boolean
    # NOTE: This does not handle the technical work. Refer the addPassword() for that

    # We first ask user to validate by entering the password
    passcode = checkPassword()
    manual = '-m' in args

    if passcode[0]:
        # If the user entered the incorrect password, we throw an error and return False
        password = (False, '') # This is NOT the users password. This is the variable to
        # store the password the user want to store

        if not(manual):
            # Here we check of the user requested manual password. If not we first check if
            # user has entered any parameters. If so we first extract the length of the password
            # from first arguement as this is what the first arguement must be if arguements are
            # present. The rest are also checked. If no arguements are passed, we generate a
            # password with default arguements. We also set First value of password tuple to
            # know later that password is auto generated
            if (len(args) > 0):
                try:
                    passwordParams = (int(args[0]), '-u' in args, '-n' in args, '-c' in args)
                    # (length, uppercase, numbers, specialChar)
                    password = (True, randomPassword(passwordParams[0], passwordParams[1], passwordParams[2], passwordParams[3]))

                except Exception:
                    print(strVals['invalid_new_password_args'])
                    return False
            else:
                password = (True, randomPassword())

        # Here we get platform and username of the desired account
        platform = input(strVals['input_platform']).replace(' ', '_').replace('-', '_')
        username = input(strVals['input_username']).replace(' ', '_').replace('-', '_')

        # Here we check if either of them are empty or both combined make a duplicate
        # If so, we discard everything and return back
        if ((platform == '') or (username == '')):
            print(strVals['invalid_platform_inputs'])
            return False

        elif len(getUserData(passcode[1], platform, username)) > 0:
            print(strVals['duplicate_user_platform'])
            return False

        if manual:
            # We check again for manual and if so, we send to the manualPassword() function
            # that handle the manual passwords. This is done later so that for an auto
            # generation, few args has to be checked first and if an error exist in the
            # arguements passed, we must show an error and exit BEFORE we ask for user input
            # On the other hand, if manual, the password has to be handled AFTER user enters
            # the platform and username data and these are validated
            password = manualPassword()

        if password[0]:
            # Here we check if the new password is ready for assigning. This is put in place
            # so that we know if auto generation failed or manual password attempt failed.
            # This makes sure no data is entered to the database in case of an erroneous
            # password
            try:
                # First we show a warning asking whether the user is ok with the new password
                print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
                warning = input(strVals['proceed_warning_question_with_show'])

                # We loop to make sure incorrect inputs are not accepted. Only 'Y' (Yes), 'N' (No)
                # and 'S' (Show password) is acceptable. Y and N can only exit from the loop
                while (not((warning == 'Y') or (warning == 'N'))):
                    # Entering 'S' will show the user the new password that the application is
                    # ready to store. This is not shown by default for security purposes.
                    if(warning == 'S'):
                        print(strVals['show_password'].replace('<p>', password[1]))
                    
                    print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
                    warning = input(strVals['proceed_warning_question_with_show'])

                if (warning == 'Y'):
                    # Finally we check if 'Y' is given which means that the user accepts
                    # NOTE: Need improvements here. Decide if to show or not show password.
                    #       Also implement function to automatically copy password to clipboard!
                    if addPassword(passcode[1], platform, username, password[1]):
                        print(strVals['password_added_successfully'])

                else:
                    # In case the reply was otherwise, we show an aborted message and exit
                    print(strVals['user_abort'])

                return True

            except Exception as err:
                # This is for error handling
                print(strVals['fatal_error'].replace('<l>', 'addPassword').replace('<e>', err))

                return False

    return False

def deleteProfile(args):
    # DELETE PROFILE FUNCTION
    # Handles the user side tasks to delete an existing password from the system. This will handle messages,
    # error checks, and inputs.
    # Accepts args as list of Strings / Return success as Boolean
    # NOTE: This does not handle the technical work. Refer the deletePassword() for that
    
    if len(args) == 2:
        platform = args[0]
        username = args[1]

        try:
            # First we show a warning asking whether the user is ok with deleting the password
            print(strVals['delete_password_warning'])
            print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
            warning = input(strVals['proceed_warning_question'])

            # We loop to make sure incorrect inputs are not accepted. Only 'Y' (Yes), 'N' (No)
            # Y and N can only exit from the loop
            while (not((warning == 'Y') or (warning == 'N'))):
                print(strVals['delete_password_warning'])
                print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
                warning = input(strVals['proceed_warning_question'])

            if (warning == 'Y'):
                # Finally we check if 'Y' is given which means that the user accepts
                passcode = checkPassword() # Checking password

                if passcode[0]:
                    if deletePassword(passcode[1], platform, username):
                        print(strVals['password_deleted_successfully'])
                        dumpDatabase()

            else:
                # In case the reply was otherwise, we show an aborted message and exit
                print(strVals['user_abort'])

            return True

        except Exception as err:
            # This is for error handling
            print(strVals['fatal_error'].replace('<l>', 'deletePassword').replace('<e>', err))

    else:
        print(strVals['invalid_delete_password_args'])

    return False

def editProfile(args):
    # EDIT PASSWORD FUNCTION
    # Handles the user side tasks to edit an existing password to the system. This will handle messages,
    # error checks, and inputs.
    # Accepts args as list of Strings / Return success as Boolean
    # NOTE: This does not handle the technical work. Refer the editPassword() for that

    # We first ask user to validate by entering the password
    passcode = checkPassword()
    manual = '-m' in args

    if (len(args) < 2):
        print(strVals['invalid_edit_password_args'])
        return False

    # Here we extract platform and username of the desired account from arguements
    platform = args[0].replace(' ', '_').replace('-', '_')
    username = args[1].replace(' ', '_').replace('-', '_')

    if passcode[0]:
        # If the user entered the incorrect password, we throw an error and return False
        password = (False, '') # This is NOT the users password. This is the variable to
        # store the password the user want to store

        if not(manual):
            # Here we check of the user requested manual password. If not we first check if
            # user has entered any parameters. If so we first extract the length of the password
            # from first arguement as this is what the first arguement must be if arguements are
            # present. The rest are also checked. If no arguements are passed, we generate a
            # password with default arguements. We also set First value of password tuple to
            # know later that password is auto generated
            if (len(args) > 2):
                try:
                    passwordParams = (int(args[2]), '-u' in args, '-n' in args, '-c' in args)
                    # (length, uppercase, numbers, specialChar)
                    password = (True, randomPassword(passwordParams[0], passwordParams[1], passwordParams[2], passwordParams[3]))

                except Exception:
                    print(strVals['invalid_edit_password_args'])
                    return False
            else:
                password = (True, randomPassword())

        # Here we check if either of them are empty or both combined make a duplicate
        # If so, we discard everything and return back
        if ((platform == '') or (username == '')):
            print(strVals['invalid_platform_inputs'])
            return False

        elif len(getUserData(passcode[1], platform, username)) == 0:
            print(strVals['no_user_platform'])
            return False

        if manual:
            # We check again for manual and if so, we send to the manualPassword() function
            # that handle the manual passwords. This is done later so that for an auto
            # generation, few args has to be checked first and if an error exist in the
            # arguements passed, we must show an error and exit BEFORE we ask for user input
            # On the other hand, if manual, the password has to be handled AFTER user enters
            # the platform and username data and these are validated
            password = manualPassword()

        if password[0]:
            # Here we check if the new password is ready for assigning. This is put in place
            # so that we know if auto generation failed or manual password attempt failed.
            # This makes sure no data is entered to the database in case of an erroneous
            # password
            try:
                # First we show a warning asking whether the user is ok with the new password
                print(strVals['edit_password_warning'])
                print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
                warning = input(strVals['proceed_warning_question_with_show'])

                # We loop to make sure incorrect inputs are not accepted. Only 'Y' (Yes), 'N' (No)
                # and 'S' (Show password) is acceptable. Y and N can only exit from the loop
                while (not((warning == 'Y') or (warning == 'N'))):
                    # Entering 'S' will show the user the new password that the application is
                    # ready to store. This is not shown by default for security purposes.
                    if(warning == 'S'):
                        print(strVals['show_password'].replace('<p>', password[1]))
                    
                        print(strVals['edit_password_warning'])
                        print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
                        warning = input(strVals['proceed_warning_question_with_show'])

                if (warning == 'Y'):
                    # Finally we check if 'Y' is given which means that the user accepts
                    # NOTE: Need improvements here. Decide if to show or not show password.
                    #       Also implement function to automatically copy password to clipboard!
                    if editPassword(passcode[1], platform, username, password[1]):
                        print(strVals['password_changed_successfully'])

                else:
                    # In case the reply was otherwise, we show an aborted message and exit
                    print(strVals['user_abort'])

                return True

            except Exception as err:
                # This is for error handling
                print(strVals['fatal_error'].replace('<l>', 'editPassword').replace('<e>', err))

                return False

    return False

def showPassword(args):
    # COPY PASSWORD FUNCTION
    # Allows user to see the password quickly from username and password
    # Accepts args as list of Strings / Return success as Boolean

    # We first ask user to validate by entering the password
    passcode = checkPassword()

    if (len(args) < 2):
        print(strVals['invalid_view_password_args'])
        return False

    # Here we extract platform and username of the desired account from arguements
    platform = args[0]
    username = args[1]

    if passcode[0]:
        # If the user entered the incorrect password, we throw an error and return False
        userInformation = getUserInformation(passcode[1], platform, username)

        if len(userInformation) > 0:
            # We get the password info from getUserInformation() function for the
            # provided username and platform combination and we copy the first
            # returned value if we have more that zero data and show an error if not
            print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
            print(strVals['show_password_with_info'].replace('<p>', userInformation[0][0]).replace('<d>', userInformation[0][1]))
        
        else:
            print(strVals['user_or_platform_not_exist'])

    return False

def copyPassword(args):
    # COPY PASSWORD FUNCTION
    # Allows user to copy the password quickly from username and password
    # Accepts args as list of Strings / Return success as Boolean

    # We first ask user to validate by entering the password
    passcode = checkPassword()

    if (len(args) < 2):
        print(strVals['invalid_edit_password_args'])
        return False

    # Here we extract platform and username of the desired account from arguements
    platform = args[0]
    username = args[1]

    if passcode[0]:
        # If the user entered the incorrect password, we throw an error and return False
        userInformation = getUserInformation(passcode[1], platform, username)

        if len(userInformation) > 0:
            # We get the password info from getUserInformation() function for the
            # provided username and platform combination and we copy the first
            # returned value if we have more that zero data and show an error if not
            print(strVals['show_username_platform'].replace('<p>', platform).replace('<u>', username))
            try:
                pc.copy(userInformation[0][0])
            except:
                print(strVals['copy_error'])
            print(strVals['password_copied_successfully'])
        
        else:
            print(strVals['user_or_platform_not_exist'])

    return False

def showPlatforms(args):
    # SHOW PLATFORMS FUNCTION
    # This allows users to list all the platforms registered in the
    # database. They can also include a keyword as arguement to
    # search for a matching phrase

    # We first ask user to validate by entering the password
    passcode = checkPassword()

    if passcode[0]:
        rows = 5 # Number of rows to display
        keyword = '' # Keyword user included in arguements

        if (len(args) > 1):
            # If the arguement count is more than one, the second arguement must
            # be an integer that define how many rows to show. If it's wrong we
            # assume default value
            try:
                rows = int(args[1])
            except:
                print(strVals['invalid_search_args'])

        if (len(args) > 0):
            # If the arguement count is more than 0, then we have a keyword. So
            # we extract the keyword and show a message. Otherwise we just get
            # all entries
            keyword = args[0]
            print(strVals['show_keyword_platforms'].replace('<k>', keyword))

        else:
            print(strVals['show_all_platforms'])

        platforms = getPlatformNames(passcode[1], keyword)
        output = ''

        # Finally we list all platforms. This is done in rows for easier visibility
        # separated by a |
        if len(platforms) == 0:
            print('     ~~EMPTY~~')
        else:
            for i in range(len(platforms)):
                output += platforms[i]

                if (i % rows) == rows - 1:
                    output += ' \n'
                else:
                    output += ' | '

            output = output[:-2]
        print(output)

        return True

    return False

def showUsernames(args):
    # SHOW USERNAMES FUNCTION
    # This allows users to list all the platforms and users registered in the
    # database. They can also include a keyword as arguement to search for
    # a matching phrase

    # We first ask user to validate by entering the password
    passcode = checkPassword()

    if passcode[0]:
        rows = 5 # Number of rows to display
        keyword = '' # Keyword user included in arguements
        platform = '' # Keyword user included in arguements for platform

        if (len(args) > 2):
            # If the arguement count is more than two, the thirt arguement must
            # be an integer that define how many rows to show. If it's wrong we
            # assume default value
            try:
                rows = int(args[2])
            except:
                print(strVals['invalid_search_args'])

        if (len(args) > 1):
            # If the arguement count is more than 1, then we have two keyword. So
            # we extract the keywords and show a message. Otherwise we just get
            # all entries
            keyword = args[0]
            platform = args[1]

            if keyword == '-a':
                keyword = ''
                print(strVals['show_all_usernames_in_keyword_platforms'].replace('<p>', platform))
            else:
                print(strVals['show_keyword_usernames_in_keyword_platforms'].replace('<p>', platform).replace('<k>', keyword))

        elif (len(args) == 1):
            # If the arguement count is exactly 1, then we have a keyword only. So
            # we extract the keyword and show a message. Otherwise we just get
            # all entries
            keyword = args[0]
            print(strVals['show_keyword_usernames'] .replace('<k>', keyword))

        else:
            # Otherwise we show all usernames
            print(strVals['show_all_usernames'])

        returnData = searchUsernames(passcode[1], keyword, platform)

        # Finally we list all platforms and their usernames. This is done in rows for easier visibility
        # separated by a |
        if len(returnData) == 0:
            print('     ~~EMPTY~~')
        else:
            for item in returnData:
                output = ''
                print(item[0] + ":")
                if len(item[1]) == 0:
                    output = '      ~~EMPTY~~'
                else:
                    for i in range(len(item[1])):
                        if (i % rows) == 0:
                            output += '     '

                        output += item[1][i]

                        if (i % rows) == rows - 1:
                            output += ' \n'
                        else:
                            output += ' | '

                    output = output[:-2]
                print(output)

        return True

    return False

####################################################
##### Application

# First we initialize the application
print(strVals['loading_information'])
initialize()
# Then we enter into the entry point to continue with the application
# entryPoint()

####################################################
##### DEBUG CODE
##### NOTE: COMMENT AFTER TESTING

# print(getPlatform('password', 'facebook'))
# print('\n\n')
#newProfile([])
# addPassword('password', 'insta', 'asanka', 'helloworl')
# print(getUserInformation('password', 'insta', 'asanka'))
#editProfile(input('Edit').split(' '))
#editPassword('password', 'insta', 'asanka', 'helloworld')
entryPoint()
# print(getUserInformation('password', 'insta', 'asanka'))
# deletePassword('password', 'insta', 'asanka')
#deleteProfile(['insta', 'asanka'])
# print(getUserInformation('password', 'insta', 'asanka'))
#showPlatforms(['a'])
#showUsernames(['p', 'a', '1'])