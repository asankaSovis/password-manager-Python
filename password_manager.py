################################################
## 
## This is a basic password manager made in python
## Project start: 08/01/2022 6:00am
################################################

from os.path import exists

database = ''

def initialize():
    if not(exists('database.en')):
        print('')
    database = open('database.en','w+')


def entryPoint():
    while(True):
        response = input('>>> ')
        if(response == 'exit'):
            if database != '':
                database.close()
            quit()
        else:
            print('Unknown Command')

initialize()
entryPoint()