<h1 align="center">
  Offline My_Password_Man
</h1>
<p align="center">
  <img src="logo.png" alt="Password Manager">
</p>
The Offline My_Password_Man (written in Python for Windows only) is a GUI-based password manager tool that operates offline to securely store and manage your passwords and sensitive information. It can be run on USB for maximum security, by using the autorun function in Windows.                     


         
## Features

- **Offline Operation**: The password manager operates completely offline, ensuring your data remains private and secure.
- **Password Management**: Easily add, remove, and reveal stored passwords, providing a convenient way to manage your credentials.
- **Password Generation**: Generate strong and secure passwords on demand to enhance your online security.
- **Data Encryption**: All data files are encrypted to ensure the confidentiality of your stored information.
- **Authentication**: Protect your password manager with a strong master password, providing an additional layer of security.



## Usage

1. Download and install the Offline Password Manager on your local machine or USB device.
2. Launch the application and set up a master password for authentication.
3. Use the provided options to add, remove, reveal, or generate passwords.
4. Your data will be encrypted and securely stored within the password manager.
5. USB option: It can run via USB device using autorun function in Windows.



## Installation

1. Clone this repository to your local machine.
2. Install the required dependencies by running the following command:

   ```shell
   cd <repo-path>
   pip install -r requirements.txt
   python First_Time.py
3) After that to open the manager, run this command:

   ```shell
   python my_pass_manager.py
4) When wanting to create a new user:
- **Using the same data file**: Decrypt the data files (data.py, data.json) with the private key. Then run the First_Time.py script.
- **renew the data files**: Remove the old data files (data.py, data.json)
and download those fresh files. Then run the First_Time.py.
NOTE: If you create a user and key, you need to work only with the my_pass_manager.py
   

