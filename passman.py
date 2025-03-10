import os
import json
import secrets
import getpass
import string
import pyotp
import qrcode
from cryptography.fernet import Fernet

# Load or generate encryption key
def load_key():
    key_file = "key.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except Exception as e:
            print("Error loading encryption key:", e)
            return None
    return key

# Encrypt & decrypt functions
def encrypt(text, key):
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt(text, key):
    return Fernet(key).decrypt(text.encode()).decode()

# Generate a strong password
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation.replace("\\", "").replace("'", "").replace("\"", "")
    return "".join(secrets.choice(chars) for _ in range(length))

# Setup MFA
def setup_mfa():
    key = load_key()
    if key is None:
        return None
    
    mfa_file = "mfa_secret.json"
    if os.path.exists(mfa_file):
        try:
            with open(mfa_file, "r") as f:
                return decrypt(json.load(f)["secret"], key)
        except (json.JSONDecodeError, Exception):
            print("Error: MFA secret file is corrupted. Resetting MFA...")
    
    secret = pyotp.random_base32()
    with open(mfa_file, "w") as f:
        json.dump({"secret": encrypt(secret, key)}, f)
    
    qr = qrcode.make(pyotp.TOTP(secret).provisioning_uri("User", "PasswordManager"))
    qr.show()
    return secret

# Verify MFA
def verify_mfa(secret):
    totp = pyotp.TOTP(secret)
    for _ in range(3):
        if totp.verify(input("Enter MFA Code: ")):
            return True
        print("Invalid code, try again.")
    return False

# Master Password Handling
def set_master_password():
    master_file = "master.json"
    key = load_key()
    if key is None:
        return None
    
    if os.path.exists(master_file):
        with open(master_file, "r") as f:
            return decrypt(json.load(f)["master"], key)
    
    master_password = getpass.getpass("Set Master Password: ")
    with open(master_file, "w") as f:
        json.dump({"master": encrypt(master_password, key)}, f)
    print("Master password set!")
    return master_password

def verify_master_password(master_password):
    for _ in range(3):
        if getpass.getpass("Enter Master Password: ") == master_password:
            return True
        print("Incorrect password, try again.")
    return False

# Save & retrieve passwords
def save_password(service, username, password, key):
    file = "passwords.json"
    data = {}
    if os.path.exists(file):
        try:
            with open(file, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print("Error: Password file is corrupted. Resetting file...")
            data = {}
    
    data[service] = {"username": username, "password": encrypt(password, key)}
    try:
        with open(file, "w") as f:
            json.dump(data, f, indent=4)
        print("Password saved!")
    except Exception as e:
        print("Error saving password:", e)

def get_password(service, key):
    file = "passwords.json"
    if os.path.exists(file):
        try:
            with open(file, "r") as f:
                data = json.load(f)
                if service in data:
                    print(f"Service: {service}\nUsername: {data[service]['username']}\nPassword: [HIDDEN]")
                    return decrypt(data[service]['password'], key)
        except json.JSONDecodeError:
            print("Error: Password file is corrupted.")
    print("Service not found.")
    return None

# Main function
def main():
    key = load_key()
    if key is None:
        print("Error: Unable to load encryption key. Exiting.")
        return
    
    master_password = set_master_password()
    if master_password is None:
        print("Error: Master password setup failed. Exiting.")
        return
    
    if not verify_master_password(master_password):
        print("Master password authentication failed. Exiting.")
        return
    
    while True:
        print("\n" + "="*30)
        print("      PASSWORD MANAGER")
        print("="*30)
        print("[1] Save Password")
        print("[2] Retrieve Password")
        print("[3] Generate Password")
        print("[4] Setup MFA (Optional)")
        print("[5] Exit")
        print("="*30)
        
        choice = input("Enter choice: ")
        
        if choice == "1":
            save_password(input("Service: "), input("Username: "), getpass.getpass("Password: "), key)
        elif choice == "2":
            service = input("Service: ")
            decrypted = get_password(service, key)
            if decrypted:
                print("Password:", decrypted)
        elif choice == "3":
            print("Generated Password:", generate_password())
        elif choice == "4":
            mfa_secret = setup_mfa()
            if mfa_secret and verify_mfa(mfa_secret):
                print("MFA setup successful!")
            else:
                print("MFA setup failed or skipped.")
        elif choice == "5":
            print("Exiting... See ya!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
