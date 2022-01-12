# 🔐 password-manager
Password manager is a password manager designed to make managing passwords easy and secure. My goal is to make it a secure and reliable password manager available in the public domain for everyone to use. Privacy and security is for everyone, this is the core value behind this project. It uses [Fernet encryption](https://cryptography.io/en/latest/fernet/) to encrypt passwords and store them on a database. It uses two factor authentication with a password and randomly generated salt to encrypt the database. The application is built to be as simple as possible to make sure it's secure. On the other hand, this project is an experiment to see how to make a better security application.

Please note that I am still learning and this project has also been a way to expand my knowledge. Any suggestions, issues and ideas are more than welcome. On the other hand, this application is still in its alpha phase. Therefore please don't use it solely for personal usage. It might have severe bugs and issues regarding functionality and security.

## Dependencies
- [Cryptography](https://cryptography.io/en/latest/fernet/) - This module is used for all the cryptographic work. This is an important library.
- [Pyperclip](https://pyperclip.readthedocs.io/en/latest/) - This module is only used for copying content to the clipboard. Can be skipped if not necessary.

## Usage
The application has several useful commands built in. These allow for adding, editing, deleting and also viewing passwords to and from the database.
- ❓ help - This command will list out help information for the application.
  - `help`    [List out all the commands and their details]
  - `help <command>`  [This will list out information for the specified command]
- ⛔ exit - This command will exit the application.
- ❗ about - This command will show the about information of the application.
- 🕓 version - This command will show the version number of the application that you're using.
- ➕ add - This command will add a new profile to the database.
  - `add`    [Loads the add command with auto-generated password of default size and character set]
  - `add <size> <arguements>`    [Loads the add command with auto-generated password of size provided and character set provided]
  - `add -m`    [Loads the add command with a manual password]
      > arguement set - -u(Include uppercase) -n(Include numbers) -c(Include special characters)
      > 
      > *ex: 'add 13 -c -u' will auto-generate a password 13 characters long with only lowercase, uppercase and special characters*
- ✏️ edit - This command will edit an existing profile in the database.
  - `edit <platform> <username>`    [Loads the edit command with auto-generated password of default size and character set for the provided platform and username]
  - `edit <platform> <username> <size> <arguements>`    [Loads the edit command with auto-generated password of size provided and character set provided]
  - `edit <platform> <username> -m`    [Loads the edit command with a manual password]
      > arguement set - -u(Include uppercase) -n(Include numbers) -c(Include special characters)
      > 
      > *ex: 'edit Instagram Frank 13 -c -u' will auto-generate a password 13 characters long with only lowercase, uppercase and special characters*
- 🗑️ delete - This command will delete an existing profile in the database.
  - `delete <platform> <username>`    [Loads the delete command for the platform and username]
- 👀 show - This command will show the password of an existing profile in the database.
  - `show <platform> <username>`    [Loads the show command for the platform and username]
- 🗒️ copy - This command will copy the password of an existing profile in the database.
  - `copy <platform> <username>`    [Loads the copy command for the platform and username]
- 🌏 platform - This command will list out the platforms in the database.
  - `platform`    [Will list all the platforms listed in the database]
  - `platform <keyword>`    [Will list all the platforms listed in the database that match the keyword]
  - `platform <keyword> <row>`    [Will list all the platforms listed in the database that match the keyword and will list them in the specified row count]
- 👩‍🦰 username - This command will list out the usernames in the database.
  - `username`    [Will list all the usernames listed in the database]
  - `username <keyword>`    [Will list all the usernames listed in the database that match the keyword]
  - `username <keyword> <platform>`    [Will list all the usernames listed in the database that match the keyword and platform name]
  - `username -a <platform>`    [Will list all the usernames listed in the database that match only the platform name]
  - `username <keyword or -a> <platform> <rows>`    [Will list all the usernames listed in the database that match the keyword (or all if -a is provided) and platform name and will list them in the specified row count]

## Implementation
The database is a basic text file and data is stored to it in JSON format. However, each item stored as an encrypted string, encrypted using the Fernet encryption.

![database_structure](https://user-images.githubusercontent.com/46389631/149176881-a137705f-0d34-4845-a72d-d3b02b7c2fd3.png)

`{"Platform 01" : [{"User 01" : ["Password", "Modified Date"]}, ...], ...}`

Each of these parameters are encrypted individually. Fernet encryption required a salt and password to decrypt text. Thus, we can modify the password to store different items in different formats.

![encryption_algorithm](https://user-images.githubusercontent.com/46389631/149184992-509823a7-61f7-43a7-8d5c-781a982cd795.png)

## Releases

#### Version 1.0.0 Alpha (Initial) [12/01/2022]
- Support for Encryption
- Add, Edit, Delete functionality
- Viewing and copying functionality
- Help and About sections
- Setting up a passcode

📝 *NOTE: Throughout the application, Passcode refers to the root password set for the password manager and Password refers to the password of the application.*

    © 2022 Asanka Sovis
