import tkinter as tk
import time
import string
from tkinter import messagebox
import sqlite3
from random import sample as shuf


class UserRandom:
    def __init__(self, seed):
        self.seed = seed

    def randrange(self, start, stop):
        self.seed = (self.seed * 1103515245 + 12345) & 0xFFFFFFFF
        return start + (self.seed % (stop - start))

def generate_random_seed():
    current_time = int(time.time())
    seed = current_time % 100000 
    return seed
    
seed = generate_random_seed()
user_random = UserRandom(seed)

def generate_password():
    length = password_length.get()

    if not length.isdigit():
        messagebox.showerror("Error", "Please enter a valid password length.")
        return

    length = int(length)

    if length < 12 or length >= 32:
        messagebox.showerror("Error", "Please enter a password length greater than 12 and smaller than 32.")
        return

    lowercase_characters = string.ascii_lowercase # all the lower charater in string form 'abcdefghijklmnopqrstuvwxyz'
    uppercase_characters = string.ascii_uppercase # 
    special_characters = string.punctuation  # "!@#$%^&*()_+"
    digit_characters = string.digits # "1234567890"

    allcharacter = lowercase_characters+uppercase_characters+special_characters+digit_characters

    banned_words = banned_words_entry.get().split(',')

    if banned_words == ['']:
        banned_words = [] 

    global user_random
    password = ""

    while True:
        # 1 lower case , 2 digit , 1 special charater , 2 uppercase minimum requirement
        password = lowercase_characters[user_random.randrange(0, len(lowercase_characters))] # lowercase_char[14]
        password += ''.join(digit_characters[user_random.randrange(0, len(digit_characters))] for _ in range(2))
        password += special_characters[user_random.randrange(0, len(special_characters))] # for 1 special char
        password += ''.join(uppercase_characters[user_random.randrange(0, len(uppercase_characters))] for _ in range(2)) # for 2 uppercase charater

        if len(password) < length:
            remaining_length = length - len(password)
            password += ''.join(allcharacter[user_random.randrange(0, len(allcharacter))] for _ in range(remaining_length))

        password = ''.join(shuf(password, len(password)))

        if all(word not in password for word in banned_words):
            break

    password_entry.delete(0, tk.END)
    password_entry.insert(tk.END, password)

def copy_password():
    password = password_entry.get()

    if password:
        window.clipboard_clear()
        window.clipboard_append(password)
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showwarning("No Password", "No password generated yet.")

def save_password():
    password = password_entry.get()
    purpose = purpose_entry.get()

    if not password:
        messagebox.showwarning("No Password", "No password generated yet.")
        return

    if not purpose:
        messagebox.showwarning("Missing Purpose", "Please enter a password purpose.")
        return

    # Connect to the SQLite database
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    # Create a table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      purpose TEXT,
                      password TEXT)''')

    # Insert the purpose and password into the table
    cursor.execute("INSERT INTO passwords (purpose, password) VALUES (?, ?)",
                   (purpose, password))

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password saved to the database.")


# Create the main window
window = tk.Tk()
window.title("Random Password Generator")
window.geometry("1080x720")

# Frame for password generation
generation_frame = tk.LabelFrame(window, text="Password Generation")
generation_frame.pack(pady=20)

# Password Length
password_length_label = tk.Label(generation_frame, text="Password Length:")
password_length_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)

password_length = tk.Entry(generation_frame, width=30)
password_length.grid(row=0, column=1, padx=10, pady=10)

# Banned Words
banned_words_label = tk.Label(generation_frame, text="Banned Words (comma-separated):")
banned_words_label.grid(row=1, column=0, sticky="w", padx=10)

banned_words_entry = tk.Entry(generation_frame, width=30)
banned_words_entry.grid(row=1, column=1, padx=10)

# Generate Password Button
generate_button = tk.Button(generation_frame, text="Generate Password", command=generate_password)
generate_button.grid(row=2, columnspan=2, pady=10)

# Frame for displaying and saving password
display_frame = tk.LabelFrame(window, text="Generated Password")
display_frame.pack(pady=20)

# Password Entry
password_entry = tk.Entry(display_frame, width=30)
password_entry.grid(row=0, column=0, padx=10, pady=10)

# Copy Password Button
copy_button = tk.Button(display_frame, text="Copy Password", command=copy_password)
copy_button.grid(row=1, column=0, pady=10)

# Password Purpose
purpose_label = tk.Label(display_frame, text="Password Purpose:")
purpose_label.grid(row=0, column=1, sticky="w", padx=10)

purpose_entry = tk.Entry(display_frame, width=30)
purpose_entry.grid(row=0, column=2, padx=10)

# Save Password Button
save_button = tk.Button(display_frame, text="Save Password", command=save_password)
save_button.grid(row=1, column=2, pady=10)

window.mainloop()

