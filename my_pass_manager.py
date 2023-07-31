##############################################################################
# Offline My_Password_Man - Python Script
# Description: A GUI-based password manager tool that operates offline to securely store and manage your passwords and sensitive information. It can be run on USB for maximum security, by using the autorun function in Windows.
# Author: Dor Dahan
# License: MIT (See details in the LICENSE file or at the end of this script)
##############################################################################
import os
from tkinter import *
from tkinter import messagebox
from pyperclip import copy
from tkinter import ttk
import json, subprocess, random, hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ---------------------------- VARIABLES ------------------------------- #

# # style
FONT= ("Arial", 10, "bold")
BG = "#FFFEC4"
image_color="#CBFFA9"
TEXT_BG="white"

# # can be change to be the same email or username
EMAIL = "****@gmail.com"

# ---------------------------- Decryption process ------------------------------- #

PASS = b"dor"

def decrypt_process(ciphertext_bytes, private_key):
    """
    Decrypting the input using the private key
    :param ciphertext_bytes: The encrypted input
    :param private_key: The private key
    :return: The decrypted output
    """
    plaintext = private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# ---------------------------- Decryption  ------------------------------- #

def decrypt(file_path):
    """
    Decrypting the files for getting the values
    :param file_path: The file path
    :return:
    """
    with open('private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=PASS,
            backend=default_backend()
        )
    if file_path.endswith(".json"):
        with open(file_path, "rb") as file:
            ciphertext = file.read()
            # Determine the block size based on the private key size
            block_size = private_key.key_size // 8
            if len(ciphertext) > block_size:
                plaintext = b""
                start = 0
                while start < len(ciphertext):
                    end = start + block_size
                    plaintext += decrypt_process(ciphertext[start:end], private_key)
                    start = end
            else:
                plaintext = decrypt_process(ciphertext, private_key)
    else:
        with open(file_path, "rb") as file:
            ciphertext_bytes = file.read()
            plaintext = decrypt_process(ciphertext_bytes, private_key)
    with open(file_path, "wb") as file:
        file.write(plaintext)

# ---------------------------- Decryption Process ------------------------------- #

def start_decrypet():
    """
    Check if the data files are encrypted or not.
    :return:
    """
    with open("data.json", "rb") as file:
        file_content = file.read()
        if file_content.startswith(b"{\r"):
            pass
        else:
            decrypt("data.json")
    with open("data.py", "rb") as file:
        file_content = file.read()
        if file_content.startswith(b"PASSWORD"):
            pass
        else:
            decrypt("data.py")

with open("private_key.pem", "rb") as key_file:
    private_key_pem = key_file.read()
private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=PASS,
    backend=default_backend()
)

with open("public_key.pem", "rb") as key_file:
    public_key_pem = key_file.read()
public_key = serialization.load_pem_public_key(
    public_key_pem,
)

start_decrypet()

# ---------------------------- Variables for control ------------------------------- #

letters = 0
upper = 0
numbers = 0
symbols = 0
num = 0
num1 = 0

# ---------------------------- Encryption ------------------------------- #

def on_close():
    """
    When pressing on exit from the script it will encrypt back the infomation
    :return:
    """
    def encrypt_process(plaintext_bytes):
        """
        Encrypting the input you insert using the public key
        :param plaintext_bytes: The bytes that need to be encrypted
        :return: Encrypt output
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
        Encrypt back the files
        :param file_path: File path to encrypt
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

    encrypt("data.json")
    encrypt("data.py")
    window.destroy()

# ---------------------------- Authentication ------------------------------- #

from data import MD5

def main():
    """
    The start of the script for getting to the manager
    :return:
    """
    global  window
    def check(event=""):
        """
        Check if the password is correct or not (by the MD5 hash)
        :return: Continue the script or error
        """
        value = entry.get()
        bytes_value = value.encode('utf-8')
        hash = hashlib.md5(bytes_value).hexdigest()
        if hash == MD5:
            label.destroy()
            button.destroy()
            entry.destroy()
            window.destroy()
            manager()
        else:
            messagebox.showerror(title="Error - Wrong Password",message="The password you entered is not right.")
    window = Tk()
    window.title("MyPass - Login")
    window.protocol("WM_DELETE_WINDOW", on_close)
    window.iconbitmap("logo.ico")
    window.resizable(False, False)
    window.config(bg=BG, pady=20, padx=20, borderwidth=2, relief="raised")

    canvas = Canvas(window, width=200, height=200, bg=image_color, highlightthickness=0)
    img = PhotoImage(file="logo.png")
    canvas.create_image(100, 100, image=img)
    canvas.grid(column=1, row=0, pady=5)

    label = Label(text="Enter the password to access the system:", font=FONT, bg=BG)
    label.grid(column=1, row=1, pady=5)

    button = Button(text="Login", width=20, command=check)
    button.grid(column=1, row=3, pady=5)

    entry = Entry(show="*")
    entry.bind("<Return>", check)
    entry.focus()
    entry.grid(column=1, row=2, pady=5)
    window.mainloop()

# ---------------------------- Clear inputs ------------------------------- #

def clear_inputs():
    """
    Will clear all the inputs in the main screen (not the email)
    :return:
    """
    website_entry.delete(0, END)
    password_entry.delete(0, END)

# ---------------------------- Load json file ------------------------------- #

def load_json():
    """
    Load the date to variable
    :return: The json data
    """
    with open("data.json", "r") as file:
        data = json.load(file)
        return data

# ---------------------------- Change password  ------------------------------- #

def change_password():
    """
    Change the password in variables
    :return:
    """
    with open("data.py", "r") as file:
        data = file.readlines()
    with open("data.py", "w") as file:
        for line in data:
            if "PASSWORD =" in line:
                file.write(f'PASSWORD = "{new_pass_entry.get()}"\n')
            elif "MD5 =" in line:
                bytes_value = new_pass_entry.get().encode('utf-8')
                hash = hashlib.md5(bytes_value).hexdigest()
                file.write(f'MD5 = "{hash}"\n')
            else:
                file.write(line)
    win2.destroy()

# ---------------------------- reset to new password ------------------------------- #

def password_reset():
    """
    Open a windows for changing the password from the script
    :return:
    """
    global new_pass_entry, win2,num
    win2 = Tk()
    win2.title("New password")
    win2.iconbitmap("logo.ico")
    win2.iconbitmap("logo.ico")
    win2.resizable(False, False)
    win2.config(bg=BG, pady=20, padx=20, borderwidth=2, relief="raised")
    num = 2
    label_pass = Label(win2 ,text="Enter the new password:", bg=BG, font=("Arial", 12, "bold"))
    label_pass.grid(column=1, row=0, pady=10)
    new_pass_gene_butt = Button(win2, text="Generate password",command=getting_the_amount, width=30)
    new_pass_gene_butt.grid(column=1, row=3,pady=10)
    new_pass_gene_butt = Button(win2, text="Save", command=change_password , width=30)
    new_pass_gene_butt.grid(column=1, row=2,pady=10)
    new_pass_entry = Entry(win2, width=30)
    new_pass_gene_butt.focus()
    new_pass_entry.grid(column=1, row=1,pady=10)
    win2.mainloop()

# ---------------------------- Password Copy ------------------------------- #

def copy_password(event):
    """
    Copy the password from the table
    :param event: When selecting a row
    :return: Will copy the password to the clipboard
    """
    selected_item = tree.focus()
    values = tree.item(selected_item)["values"]
    try:
        password = values[2]
        if password == "*" * 15:
            password = get_passwords(tree.item(selected_item)["values"])
        copy(password)
    except IndexError:
        pass
    else:
        print("Clipboard copy")

# ---------------------------- Get Password ------------------------------- #

def get_passwords(values):
    """
    Get the password from the json file
    :param values: The values of the row
    :return: The password
    """
    data = load_json()
    return data[values[0]]["password"]

# ---------------------------- Password Table ------------------------------- #

def password_format(value=""):
    """
    Custom format for the password values (replacing characters with dots or asterisks)
    :param value: The password
    :return: The amount of astrix to enter the pass
    """
    return "*" * 15

# ---------------------------- Reveal password ------------------------------- #

def reveal_passwords():
    """
    Reveal or unrevealed the hidden/readable passwords in the "Password" row
    :return: The hidden or readable password
    """
    global num1
    if num1 == 0:
        for item in tree.get_children():
            values = tree.item(item)["values"]
            try:
                with open("data.json", "r") as data_file:
                    data = json.load(data_file)
            except FileNotFoundError:
                messagebox.showerror(title="Error - File not found", message="The file not found... \nYou need to create authentication cards before")
            password = data[values[0]]["password"]
            tree.set(item, column="Password", value=password)
            num1 = 1
    else:
        password = password_format()
        for item in tree.get_children():
            tree.set(item, column="Password", value=password)
        num1 = 0

# ---------------------------- Create a table ------------------------------- #

def read_file():
    """
    Create a table to insert the json items and display the authentication cards.
    :return: A table on the screen
    """
    global tree, edit_window, tree_butt, refresh_button, edit_button, remove_button, reveal_button
    try:
        # -------------------- Information -------------------- #

        with open("data.json", "r") as file:
            data = json.load(file)

        # -------------------- Table -------------------- #
        headers = ("Website", "Email", "Password")
        tree = ttk.Treeview(window, columns=headers, show="headings")  # Use "headings" option to hide values
        tree.column("#0", width=0, stretch="NO")
        for column in headers:
            tree.column(column, width=150)
        tree.heading("#0", text="", anchor="w")
        for column in headers:
            tree.heading(column, text=column, anchor="w")
        for index, row in enumerate(data):
            value = [row]
            if row != "website":
                for line in data[row].values():
                    value.append(line)
                values = tuple(value)
                values = values[:2] + (password_format(values[2]),) + values[3:]
                tree.insert("", "end", text=index, values=values)
            else:
                pass
        tree.grid(column=0, row=7, columnspan=3, pady=10, sticky="NSEW")
        tree.bind("<ButtonRelease-1>", copy_password)

        # -------------------- Scrollbar -------------------- #
        scrollbar = Scrollbar(window, orient="vertical", command=tree.yview, width=15, highlightthickness=0, bg="white")
        scrollbar.grid(column=3, row=7, sticky="NSW", pady=2)
        tree.configure(yscrollcommand=scrollbar.set)
        window.grid_columnconfigure(2, weight=1)

        # -------------------- Buttons -------------------- #

        refresh_button = Button(text="Refresh", width=10, command=read_file)
        refresh_button.grid(column=1, row=8, pady=5, padx=5, sticky="w")

        remove_button = Button(text="Remove", width=10, command=remove_password)
        remove_button.grid(column=2, row=8, pady=5, padx=5, sticky="w")

        edit_button = Button(text="Edit", width=10, command=edit_password)
        edit_button.grid(column=2, row=9, pady=5, padx=5, sticky="w")
        reveal_button = Button(text="Change password", width=15, command=password_reset)
        reveal_button.grid(column=0, row=9, pady=5, padx=5, sticky="w")
        reveal_button = Button(text="Un/Reveal Passwords", width=16, command=reveal_passwords)
        reveal_button.grid(column=0, row=8, pady=5, padx=5, sticky="w")
    except IndexError:
        pass

# ---------------------------- Edit password ------------------------------- #

def edit_password():
    """
    Will help us to edit the value in the JSON file from the table
    :return: messagebox of error/success
    """
    global num, website_entry1, password_entry1, edit_window, password_value

    def reveal_the_password():
        """
        Un/Reveal the text on the password(if you change befor changing
        :return:
        """
        global password_value

        if not password_entry1.get().startswith("*" * 15):
            password_value = password_entry1.get()
        if password_value.startswith("*" * 15) or password_entry1.get().startswith("*" * 15):
            password_entry1.delete(0, END)
            password_entry1.insert(0, password_value)
        else:
            password_entry1.delete(0, END)
            password_entry1.insert(0, "*" * 15)

    selected_items = tree.selection()
    if len(selected_items) == 0:
        messagebox.showerror(title="Error", message="No row selected")
        return
    if len(selected_items) > 1:
        messagebox.showerror(title="Error", message="Please select only one row to edit")
        return
    num = 1
    selected_item = selected_items[0]
    index = tree.item(selected_item)["text"]
    values = tree.item(selected_item)["values"]
    website_value = values[0]
    email_value = values[1]
    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
            password_value = data[values[0]]["password"]
    except FileNotFoundError:
        password_value = values[0]

    # -------------------- New window -------------------- #
    edit_window = Toplevel(window)
    edit_window.title("Edit Password")
    edit_window.iconbitmap("logo.ico")
    edit_window.iconbitmap("logo.ico")
    edit_window.resizable(False, False)
    edit_window.config(bg=BG, pady=20, padx=20, borderwidth=2, relief="raised")
    edit_window.config(padx=50, pady=50, bg=BG)

    # -------------------- Label -------------------- #
    website_label = Label(edit_window, text="Website:", bg=BG, font=FONT)
    website_label.grid(column=0, row=0, padx=5, pady=5)

    email_label = Label(edit_window, text="Email/Username:", bg=BG, font=FONT)
    email_label.grid(column=0, row=1, padx=5, pady=5)

    password_label = Label(edit_window, text="Password:", bg=BG, font=FONT)
    password_label.grid(column=0, row=2, padx=5, pady=5)

    # -------------------- Entry -------------------- #
    website_entry1 = Entry(edit_window, width=47, bg=TEXT_BG)
    website_entry1.grid(column=1, row=0, columnspan=4)
    website_entry1.insert(0, website_value)

    email_entry1 = Entry(edit_window, width=47, bg=TEXT_BG)
    email_entry1.grid(column=1, row=1, columnspan=4)
    email_entry1.insert(0, email_value)

    password_entry1 = Entry(edit_window, width=21, bg=TEXT_BG)
    password_entry1.grid(column=1, row=2, padx=1, pady=2, columnspan=1)
    password_entry1.insert(0, password_value)

    # -------------------- Button -------------------- #
    generate_button = Button(edit_window, text="Generate password", width=36, bg=TEXT_BG, command=getting_the_amount)
    generate_button.grid(column=2, row=2, columnspan=1, padx=3, pady=5)
    reveal_button = Button(edit_window, text="Un/Reveal", width=36, bg=TEXT_BG, command=reveal_the_password)
    reveal_button.grid(column=1, row=4, columnspan=2, padx=2, pady=5)

    save_button = Button(edit_window, text="Save", width=36, bg=TEXT_BG, command=lambda: save_edited_password(
        website_entry1.get(), password_entry1.get()
    ))
    save_button.grid(column=1, row=3, columnspan=2, padx=2, pady=5)

# ---------------------------- Save the edit password ------------------------------- #

def save_edited_password(website, password):
    """
    After editing the password, it will insert it into the JSON file
    :param website: The value inserted in the edit website
    :param password: The value inserted in the edit password
    :return: Save the edited card to the JSON file
    """
    global edit_window
    if password == 15 * "*":
        password= password_value
    confirm = messagebox.askyesno(title="Confirm Edit", message="Are you sure you want to save the changes?")
    if not confirm:
        return
    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
            if password != data[website]["password"]:
                data[website]["password"] = password
                with open("data.json", "w") as data_file:
                    json.dump(data, data_file, indent=4)
    except FileNotFoundError:
        pass
    edit_window.destroy()
    messagebox.showinfo(title="Success", message="Password updated successfully")
    read_file()

# ---------------------------- Remove password ------------------------------- #

def remove_password():
    """
    Will remove an authentication card from the table
    :return: remove a creds in the json file
    """
    selected_items = tree.selection()
    if len(selected_items) == 0:
        messagebox.showerror(title="Error", message="No row selected")
        return
    confirm = messagebox.askyesno(title="Confirm Deletion",
                                  message="Are you sure you want to delete the selected password(s)?")
    if not confirm:
        return
    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
        for item in selected_items:
            index = int(tree.item(item)["text"])
            n = 0
            for key in data.keys():
                if n == index:
                    del data[key]
                    break
                n += 1
    except FileNotFoundError:
        messagebox.showerror(title="Error - File not found",
                             message="Unable to find the JSON file.\nPlease make sure it exists.")
        return
    with open("data.json", "w") as data_file:
        json.dump(data, data_file, indent=4)
    read_file()

# ---------------------------- Get the amount of char ------------------------------- #

def getting_the_amount():
    """
    Will create new windows for the user to choose the amount of characters he/she want
    :return: New password
    """
    global window1, text_symbols_entry, text_numbers_entry, text_letters_entry,text_upper_entry

    def update_text(*args):
        """
        Creates an updated real-time amount board
        :param args: It's not meter it will be discord
        :return:
        """
        scale_used()

    def scale_used():
        """
        Create a side scale to the screen to see and update the amount label
        :return: Live indicator for the amount
        """
        global letters, numbers, symbols, upper
        letters = text_letters.get() or "0"
        upper = text_upper.get() or "0"
        numbers = text_numbers.get() or "0"
        symbols = text_symbols.get() or "0"
        amount_letters.config(text=letters)
        amount_upper.config(text=upper)
        amount_numbers.config(text=numbers)
        amount_symbols.config(text=symbols)
        update_generated_amount_label(letters=letters, upper=upper, numbers=numbers, symbols=symbols)

    def update_generated_amount_label(letters, upper, numbers, symbols):
        """
        Will update in real time the amount label of characters the user choose
        :param letters: Amount of lower letters
        :param upper: Amount of upper letter
        :param numbers: Amount of numbers
        :param symbols: Amount of symbols
        :return: A text that update in real time
        """
        total = int(letters)+int(upper)+int(numbers)+int(symbols)
        generated_amount_label.config(text=f"Generated Amount: \nLetters: {letters}\nUpper: {upper}\nNumbers: {numbers}\nSymbols: {symbols}\nTotal: {total}")

    def finish():
        """
        Will take all the new value and send to the password generator
        :return:
        """
        global letters_amount, numbers_amount, symbols_amount, upper_amount
        password_entry.delete(0, END)
        letters_amount = text_letters_entry.get()
        upper_amount = text_letters_entry.get()
        numbers_amount = text_numbers_entry.get()
        symbols_amount = text_symbols_entry.get()
        generate_password()

    letters = "0"
    upper = "0"
    numbers = "0"
    symbols = "0"

    # -------------------- New window -------------------- #
    window1 = Toplevel(window)
    window1.title("MyPass - Generator")
    window1.iconbitmap("logo.ico")
    window1.iconbitmap("logo.ico")
    window1.resizable(False, False)
    window1.config(bg=BG, pady=20, padx=20, borderwidth=2, relief="raised")

    # -------------------- Label -------------------- #

    label_gene = Label(window1, text="Generator", bg=BG, font=FONT)
    label_gene.grid(column=0, row=0, padx=5, pady=5)

    letters_label = Label(window1, text="Lower letters:", bg=BG, font=FONT)
    letters_label.grid(column=0, row=1, padx=5, pady=5)

    upper_label = Label(window1, text="Upper letters:", bg=BG, font=FONT)
    upper_label.grid(column=0, row=2, padx=5, pady=5)

    numbers_label = Label(window1, text="Numbers: ", bg=BG, font=FONT)
    numbers_label.grid(column=0, row=3, padx=5, pady=5)

    symbols_label = Label(window1, text="Symbols:", bg=BG, font=FONT)
    symbols_label.grid(column=0, row=4, padx=5, pady=5)

    amount_letters = Label(window1, text=letters, bg=BG, font=FONT)
    amount_letters.grid(column=2, row=1, padx=5, pady=5)

    amount_upper = Label(window1, text=letters, bg=BG, font=FONT)
    amount_upper.grid(column=2, row=2, padx=5, pady=5)

    amount_numbers = Label(window1, text=numbers, bg=BG, font=FONT)
    amount_numbers.grid(column=2, row=3, padx=5, pady=5)

    amount_symbols = Label(window1, text=symbols, bg=BG, font=FONT)
    amount_symbols.grid(column=2, row=4, padx=5, pady=5)

    generated_amount_label = Label(window1, text="Generated Amount: ", bg=BG, font=FONT)
    generated_amount_label.grid(column=0, row=6, columnspan=3, padx=5, pady=5)

    # -------------------- Buttons -------------------- #

    butt = Button(window1, text="Get password", command=finish)
    butt.grid(column=1, row=5)

    # -------------------- text -------------------- #

    text_letters = StringVar()
    text_letters.trace("w", update_text)
    text_upper = StringVar()
    text_upper.trace("w", update_text)
    text_numbers = StringVar()
    text_numbers.trace("w", update_text)
    text_symbols = StringVar()
    text_symbols.trace("w", update_text)

    text_letters_entry = Entry(window1, width=10, textvariable=text_letters)
    text_letters_entry.grid(column=1, row=1)
    text_letters_entry.focus()

    text_upper_entry = Entry(window1, width=10, textvariable=text_upper)
    text_upper_entry.grid(column=1, row=2)

    text_numbers_entry = Entry(window1, width=10, textvariable=text_numbers)
    text_numbers_entry.grid(column=1, row=3)

    text_symbols_entry = Entry(window1, width=10, textvariable=text_symbols)
    text_symbols_entry.grid(column=1, row=4)

# ---------------------------- Generate PASSWORD  ------------------------------- #

def generate_password():
    """
    Password generator to generate new passwords
    :return: New password
    """
    global num
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    upper = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']
    if (int(letters_amount) + int(symbols_amount) + int(numbers_amount)+ int(upper_amount)) > 11:
        password_letters = [random.choice(letters) for _ in range(int(letters_amount))]
        password_upper = [random.choice(upper) for _ in range(int(upper_amount))]
        password_symbols = [random.choice(symbols) for _ in range(int(symbols_amount))]
        password_numbers = [random.choice(numbers) for _ in range(int(numbers_amount))]
        password_list = password_letters + password_symbols + password_numbers + password_upper
        random.shuffle(password_list)
        password = "".join(password_list)
        copy(password)
        if num == 0:
            password_entry.delete(0, END)
            password_entry.insert(0, password)
        elif num == 1:
            password_entry1.delete(0, END)
            password_entry1.insert(0, password)
            num = 0
        elif num == 2:
            new_pass_entry.delete(0, END)
            new_pass_entry.insert(0, password)
            num = 0
        window1.destroy()
    else:
        messagebox.showerror(title="Error - Not enough characters", message="You need at list a 12 characters of a password...\nFix that please...")

# ---------------------------- SAVE PASSWORD ------------------------------- #

def serach():
    """
    The search button can use this function to find the website in the json file
    :return: Message Box
    """
    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
    except FileNotFoundError:
        messagebox.showinfo(title="Creating Password File", message="Creating the data.json file for saving password\n Create a item and i will show you")
        with open("data.json", "w") as data_file:
            data_file.write("{}")
    else:
        if website_entry.get() == "":
            messagebox.showerror(title="Error - Empty", message="You insert empty string for search")
        elif website_entry.get() in data:
            text = f"Website: {website_entry.get()}\n"
            text += f"Email: {data[website_entry.get()]['email']}\n"
            text += f"Password: {data[website_entry.get()]['password']}\n"
            messagebox.showinfo(title=website_entry.get(), message=text)
        else:
            messagebox.showerror(title="Error - Not found", message=f"The {website_entry.get()} is not exists...")

# ---------------------------- SAVE PASSWORD ------------------------------- #

def save_to_file():
    """
    Will save the password to the json file by using the add button
    :return:
    """
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    new_data = {website:{
        "email": email,
        "password": password
    }}
    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Please make sure you haven't left any fields empty.")
    else:
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                      f"\nPassword: {password} \nIs it ok to save?")
        if is_ok:
            try:
                with open("data.json", "r") as data_file:
                    data = json.load(data_file)
                    try:
                        del data["website"]
                    except KeyError:
                        pass
                    data.update(new_data)
            except FileNotFoundError:
                data = new_data
            finally:
                website_entry.delete(0, END)
                password_entry.delete(0, END)
            with open("data.json", "w") as data_file:
                json.dump(data,data_file, indent=4)

# ---------------------------- UI SETUP ------------------------------- #

def manager():
    """
    Start the passsword manager screen and controllers
    :return:
    """
    global window, canves, website_entry, email_entry, password_entry, generator_butten, add, clear, search_button
    """
    Create a new starting windows 
    """
    window = Tk()
    window.title("MyPass - Password Manager")
    window.iconbitmap("logo.ico")
    window.protocol("WM_DELETE_WINDOW", on_close)
    window.iconbitmap("logo.ico")
    window.resizable(False, False)
    window.config(bg=BG, pady=20, padx=20, borderwidth=2, relief="raised")

    # -------------------- Canvas -------------------- #

    """
    Establish a image to the window
    """
    canves = Canvas(window,width=200, height=200, bg=image_color, highlightthickness=0)
    img = PhotoImage(file="logo.png")
    canves.create_image(100, 100, image=img)
    canves.grid(column=1, row=0)

    # -------------------- Label -------------------- #

    """
    Adding label to what the user need to enter
    """
    label_tar = Label(window,text="Website:", bg=BG, font=FONT)
    label_tar.grid(column=0, row=1, padx=5, pady=5)

    label_user = Label(window,text="Email/Username:", bg=BG, font=FONT)
    label_user.grid(column=0, row=2, padx=5, pady=5)

    label_pass = Label(window,text="Password:", bg=BG, font=FONT)
    label_pass.grid(column=0, row=3, padx=5, pady=5)


    # -------------------- Inputs -------------------- #

    """
    Adding text input that the user can enter the input
    """
    website_entry = Entry(window, width=21, bg=TEXT_BG)
    website_entry.grid(column=1, row=1, sticky="w")
    website_entry.focus()

    email_entry = Entry(window, width=35, bg=TEXT_BG)
    email_entry.grid(column=1, row=2, columnspan=3, sticky="w")
    email_entry.insert(0, EMAIL)

    password_entry = Entry(window, width=21, bg=TEXT_BG)
    password_entry.grid(column=1, row=3, padx=1, pady=2, columnspan=1, sticky="w")

    # -------------------- Buttons -------------------- #

    """
    Adding button to the screen for the user to use a functions
    """
    generator_butten = Button(window, text="Generate Password", bg=TEXT_BG, width=14, command=getting_the_amount)
    generator_butten.grid(column=2, row=3, padx=1, pady=2, sticky="w")

    add = Button(window,text="Add", command=save_to_file, width=36, bg=TEXT_BG)
    add.grid(column=1, row=4, columnspan=2, padx=2, pady=5, sticky="w")

    clear = Button(window,text="Clear inputs", bg=TEXT_BG, width=36, command=clear_inputs)
    clear.grid(column=1, row=5, padx=1, pady=5, columnspan=2, sticky="w")

    search_button = Button(text="Search", command=serach, width=14)
    search_button.grid(row=1, column=2, pady=3, padx=3, sticky="w")
    read_file()

    # -------------------- Loop -------------------- #

    """
    Have to be on for the screen continue display even if it finish the code
    """
    window.mainloop()

# ---------------------------- Starting script ------------------------------- #

main()

# License Information
# This script is open-source and released under the MIT License.
# MIT License
# Copyright (c) 2023 Dor Dahan
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# For more details, see the LICENSE file in the root directory of this repository
# or visit https://github.com/D0rDa4aN919/MyPass_man_py.
