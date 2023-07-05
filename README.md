# Offline My_Password_Man

![Password Manager](logo.png)

The Offline My_Password_Man (written in Python for Windows only) is a GUI-based password manager tool that operates offline and can be installed on a USB device to securely store and manage your passwords and sensitive information.

**                                       NOTE: Linux in develop                            **
         
## Features

- **Offline Operation**: The password manager operates completely offline, ensuring your data remains private and secure.
- **USB Installation**: The tool can be installed on a USB device, allowing you to carry your password manager with you wherever you go.
- **Password Management**: Easily add, remove, and reveal stored passwords, providing a convenient way to manage your credentials.
- **Password Generation**: Generate strong and secure passwords on demand to enhance your online security.
- **Data Encryption**: All data files are encrypted to ensure the confidentiality of your stored information.
- **Authentication**: Protect your password manager with a strong master password, providing an additional layer of security.



## Usage

1. Download and install the Offline Password Manager on your local machine or USB device.
2. Launch the application and set up a master password for authentication.
3. Use the provided options to add, remove, reveal, or generate passwords.
4. Your data will be encrypted and securely stored within the password manager.
5. Safely back up your password manager data to ensure no data loss occurs.

## Installation

1. Clone this repository to your local machine.
2. Install the required dependencies by running the following command:

   ```shell
   cd <repo-path>
   pip install -r requirements.txt
   python First_Time.py
3) After that to opening the manager, run this command:

   ```shell
   python my_pass_manager.py
   
## USB Installation 
1. Clone this repository to your local machine.
2. Install the required dependencies by running the following command:
   ```shell
   cd <repo-path>
   pip install -r requirements.txt
   python usb_installation.py
   cd <USB-path>
   python First_Time.py
3. Disconnect the USB device.
4. From now on, any time you connect the USB device, it will open the manager.
