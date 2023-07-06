import json
import os.path
from cryptography.hazmat.primitives import padding, hashes

# ---------------------------- Variables ------------------------------- #
FONT= ("Arial", 10, "bold")
BG = "#FFFEC4"
image_color="#CBFFA9"
TEXT_BG="white"

# ---------------------------- First require information ------------------------------- #

def change_value(file_path, value, hash=None):
    """
    change the values of the data files
    :param file_path: The file path
    :param value: The value you want to change
    :param hash: The hash you want to enter.
    :return:
    """
    with open(file_path, "r") as file_obj:
        lines = file_obj.readlines()
    with open(file_path, "w") as file_write:
        for line in lines:
            if line.startswith(f"{value} = "):
                if "PASS" == value:
                    file_write.write(f'{value} = b"{entry_key.get()}"\n')
                elif "PASSWORD" == value:
                    file_write.write(f'{value} = "{entry.get()}"\n')
                elif value == "KEY":
                    file_write.write(f'{value} = "{entry_key.get()}"\n')
                elif value == "MD5":
                    file_write.write(f'{value} = "{hash}"\n')
            else:
                file_write.write(line)

def creating_sec():
    """
    Create a sing-up window
    :return:
    """
    # ---------------------------- Imports ------------------------------- #
    import hashlib
    from tkinter import Button,Entry,Tk, Label, Canvas, PhotoImage
    from tkinter import messagebox
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization

    global entry, entry_key

    def hashing():
        """
        will create the new hash from the password an insert it to the script
        :return:
        """
        bytes_value = entry.get().encode('utf-8')
        hash = hashlib.md5(bytes_value).hexdigest()
        change_value(file_path="data.py", value="PASSWORD")
        change_value(file_path="data.py", value="MD5", hash=hash)
        keys()
        win.destroy()
        import my_pass_manager

    def check(event=None):
        """
        Check password requirements
        :return:
        """
        if len(entry.get()) >= 12:
            hashing()
        else:
            messagebox.showerror(title="Error",message="You need at list 12 characters")

    def keys():
        """
        Create new public and private keys and encrypt the text
        :return:
        """
        def encrypt_process(plaintext_bytes):
            """
            Te encryption process
            :param plaintext_bytes: The plain text bytes to encrypt
            :return: The new ciphertext value
            """
            ciphertext = public_key.encrypt(
                plaintext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext

        def encrypt(file_path):
            """
            Will encrypt the passwords and important variables
            :param file_path: Path to file
            :return:
            """
            if file_path.endswith(".json"):
                with open(file_path, "rb") as file:
                    plaintext = file.read()
                    if len(plaintext) > 100:
                        ciphertext = b""
                        start = 0
                        while start < len(plaintext):
                            end = start + 100
                            ciphertext += encrypt_process(plaintext[start:end])
                            start = end
                    else:
                        ciphertext = encrypt_process(plaintext)
            else:
                with open(file_path, "rb") as file:
                    plaintext_bytes = file.read()
                    ciphertext = encrypt_process(plaintext_bytes)

            with open(file_path, "wb") as file:
                file.write(ciphertext)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        password1 = entry_key.get()
        encryption_algorithm = serialization.BestAvailableEncryption(password1.encode('utf-8'))
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        with open("private_key.pem", "wb") as key_file:
            key_file.write(private_key_pem)
        public_key = private_key.public_key()
        with open("public_key.pem", "wb") as key_file:
            key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        change_value(file_path="data.py", value="KEY")
        change_value(file_path="my_pass_manager.py", value="PASS")
        with open("public_key.pem", "rb") as key_file:
            public_key_pem = key_file.read()
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypt("data.json")
        encrypt("data.py")

    # ---------------------------- Window ------------------------------- #
    win = Tk()
    win.title("Choose a My-Pass")
    win.iconbitmap("logo.ico")
    win.config(bg=BG, padx=30, pady=30)
    # ---------------------------- Image ------------------------------- #

    canvas = Canvas(win, width=200, height=200, bg=image_color, highlightthickness=0)
    img = PhotoImage(file="logo.png")
    canvas.create_image(100, 100, image=img)
    canvas.grid(column=0, row=0, pady=5, columnspan=2)

    # ---------------------------- Label ------------------------------- #

    label = Label(text="Create a password:", font=FONT, bg=BG)
    label.grid(column=0, row=1, pady=5)
    label_key = Label(text="Create key passphrase:", font=FONT, bg=BG)
    label_key.grid(column=0, row=2, pady=5)

    # ---------------------------- Button ------------------------------- #

    button = Button(text="Check Password", width=20, command=check)
    button.grid(column=1, row=3, pady=5)

    # ---------------------------- Entry ------------------------------- #

    entry = Entry(show="*")
    entry.bind("<Return>", check)
    entry.focus()
    entry.grid(column=1, row=1, pady=5)

    entry_key = Entry(show="*")
    entry_key.bind("<Return>", check)
    entry_key.grid(column=1, row=2, pady=5)

    win.mainloop()

if __name__ == '__main__':
    creating_sec()