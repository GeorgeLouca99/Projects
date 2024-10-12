import time
import hashlib
import itertools
import string
import tkinter as tk
from tkinter import messagebox
import threading
import os

# File to store user accounts
USER_FILE = 'user_accounts.txt'

# Hashing function (SHA-256)
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Function to create a new account
def create_account():
    username = input("Enter a new username: ")
    password = input("Enter a new password: ")
    hashed_password = hash_password(password)

    with open(USER_FILE, 'a') as file:
        file.write(f"{username},{hashed_password}\n")

    print(f"Account created for {username}!")

# Function to get a user's hashed password from the file
def get_hashed_password(username: str) -> str:
    try:
        with open(USER_FILE, 'r') as file:
            for line in file:
                stored_username, stored_hash = line.strip().split(',')
                if stored_username == username:
                    return stored_hash
        print(f"User {username} not found.")
    except FileNotFoundError:
        print(f"User file '{USER_FILE}' not found.")
    return None

# Brute-force attack function
def brute_force_attack(target_hash: str, max_length: int, char_set: str):
    print(f"\nStarting brute-force attack with a max length of {max_length}...")
    for length in range(1, max_length + 1):
        for guess in itertools.product(char_set, repeat=length):
            guess = ''.join(guess)
            guess_hash = hash_password(guess)
            if guess_hash == target_hash:
                print(f"Password found: {guess}")
                return guess
    print("Password not found.")
    return None

# Dictionary attack function
def dictionary_attack(target_hash: str, wordlist_file: str):
    try:
        with open(wordlist_file, 'r') as file:
            for line in file:
                guess = line.strip()
                guess_hash = hash_password(guess)
                if guess_hash == target_hash:
                    print(f"Password found: {guess}")
                    return guess
        print("Password not found in dictionary.")
    except FileNotFoundError:
        print(f"Wordlist file '{wordlist_file}' not found.")
    return None

# Main Menu
def main_menu():
    print("=== Password Cracking Simulation ===")
    print("1. Create Account")
    print("2. Brute-force Attack")
    print("3. Dictionary Attack")
    print("4. Exit")

    choice = input("Enter your choice: ")

    if choice == '1':
        create_account_menu()
    elif choice == '2':
        brute_force_menu()
    elif choice == '3':
        dictionary_attack_menu()
    elif choice == '4':
        print("Exiting...")
    else:
        print("Invalid choice. Please try again.")
        main_menu()

# Brute-force Attack Menu
def brute_force_menu():
    username = input("Enter the username: ")
    target_hash = get_hashed_password(username)
    
    if not target_hash:
        print(f"User '{username}' does not exist.")
        main_menu()
        return

    max_length = int(input("Enter the max password length: "))
    print("Select character set: ")
    print("1. Lowercase letters")
    print("2. Lowercase + Uppercase letters")
    print("3. Lowercase + Uppercase + Numbers")
    print("4. Lowercase + Uppercase + Numbers + Symbols")

    char_choice = input("Enter your choice: ")

    if char_choice == '1':
        char_set = string.ascii_lowercase
    elif char_choice == '2':
        char_set = string.ascii_letters
    elif char_choice == '3':
        char_set = string.ascii_letters + string.digits
    elif char_choice == '4':
        char_set = string.ascii_letters + string.digits + string.punctuation
    else:
        print("Invalid choice. Using default: lowercase letters.")
        char_set = string.ascii_lowercase

    start_time = time.time()
    brute_force_attack(target_hash, max_length, char_set)
    print(f"Brute-force attack took {time.time() - start_time:.2f} seconds.")
    main_menu()

# Dictionary Attack Menu
def dictionary_attack_menu():
    username = input("Enter the username: ")
    target_hash = get_hashed_password(username)

    if not target_hash:
        print(f"User '{username}' does not exist.")
        main_menu()
        return

    wordlist_file = input("Enter the path to the wordlist file: ")

    start_time = time.time()
    dictionary_attack(target_hash, wordlist_file)
    print(f"Dictionary attack took {time.time() - start_time:.2f} seconds.")
    main_menu()

# Function to validate username and password
def validate_input(username: str, password: str) -> bool:
    if len(username.strip()) == 0:
        print("Error: Username cannot be empty.")
        return False
    if ' ' in username:
        print("Error: Username cannot contain spaces.")
        return False
    if len(password) < 6:
        print("Error: Password must be at least 6 characters long.")
        return False
    return True

# Function to check if a username already exists
def username_exists(username: str) -> bool:
    if not os.path.exists(USER_FILE):
        return False
    with open(USER_FILE, 'r') as file:
        for line in file:
            stored_username, _ = line.strip().split(',')
            if stored_username == username:
                return True
    return False

# Function to create a new account with input validation and uniqueness check
def create_account():
    while True:
        username = input("Enter a new username: ")
        password = input("Enter a new password: ")
        confirm_password = input("Confirm your password: ")

        if password != confirm_password:
            print("Error: Passwords do not match. Please try again.")
            continue

        if not validate_input(username, password):
            continue

        if username_exists(username):
            print(f"Error: Username '{username}' is already taken. Please choose another.")
            continue

        hashed_password = hash_password(password)

        # Save username and hashed password to file
        with open(USER_FILE, 'a') as file:
            file.write(f"{username},{hashed_password}\n")

        print(f"Account successfully created for {username}!")
        print(f"Hashed password (SHA-256): {hashed_password}")
        break

# Enhanced Account creation menu (called from the main menu)
def create_account_menu():
    print("=== Create a New Account ===")
    create_account()
    print("Returning to the main menu...\n")
    main_menu()

# GUI Functionality (Optional)
def run_attack():
    target_hash = get_hashed_password(hash_entry.get())
    method = attack_method.get()
    max_length = int(length_entry.get())

    if method == "Brute-force":
        char_set = string.ascii_lowercase
        brute_force_attack(target_hash, max_length, char_set)
    elif method == "Dictionary":
        wordlist = wordlist_entry.get()
        dictionary_attack(target_hash, wordlist)
    
    messagebox.showinfo("Result", "Attack completed!")

# Create the Tkinter window
window = tk.Tk()
window.title("Password Cracking Simulation")

# Attack method selection
tk.Label(window, text="Choose Attack Method").grid(row=0)
attack_method = tk.StringVar(value="Brute-force")
tk.Radiobutton(window, text="Brute-force", variable=attack_method, value="Brute-force").grid(row=1, sticky=tk.W)
tk.Radiobutton(window, text="Dictionary", variable=attack_method, value="Dictionary").grid(row=2, sticky=tk.W)

# Target hash input
tk.Label(window, text="Enter Username:").grid(row=3)
hash_entry = tk.Entry(window)
hash_entry.grid(row=4)

# Max length for brute-force
tk.Label(window, text="Max Length (for Brute-force):").grid(row=5)
length_entry = tk.Entry(window)
length_entry.grid(row=6)

# Wordlist path for dictionary attack
tk.Label(window, text="Wordlist File (for Dictionary):").grid(row=7)
wordlist_entry = tk.Entry(window)
wordlist_entry.grid(row=8)

# Run attack button
run_button = tk.Button(window, text="Run Attack", command=run_attack)
run_button.grid(row=9)

# Run the GUI
window.mainloop()

# Run the program
if __name__ == "__main__":
    main_menu()
