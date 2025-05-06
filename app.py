import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

USERS_DATA = "users.json"

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

# --- Data Handling ---
def load_data():
    if os.path.exists(USERS_DATA):
        if os.path.getsize(USERS_DATA) == 0:
            return {}
        with open(USERS_DATA, "r") as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def save_data(data):
    with open(USERS_DATA, "w") as f:
        json.dump(data, f)

# --- Password Hashing ---
def generate_salt():
    return os.urandom(16)

def hash_password(password, salt=None):
    if salt is None:
        salt = generate_salt()
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return {
        "salt": salt.hex(),
        "hash": hash_bytes.hex()
    }

def verify_password(password, stored_hash, stored_salt):
    salt_bytes = bytes.fromhex(stored_salt)
    hash_check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000).hex()
    return hash_check == stored_hash

# --- Encryption / Decryption ---
def derive_key(passkey, salt):
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return urlsafe_b64encode(key)

def encrypt_text(text, passkey, salt):
    key = derive_key(passkey, salt)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey, salt):
    try:
        key = derive_key(passkey, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --- App Logic ---
stored_data = load_data()
st.title("🔐 Secure Vault - Encrypt & Decrypt Data")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Delete Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Register ---
if choice == "Register":
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")

    if st.button("Register User"):
        if username and password:
            if username in stored_data:
                st.error("User already exists")
            else:
                hashed = hash_password(password)
                stored_data[username] = {
                    "password": hashed,
                    "data": [],
                    "encryption_salt": generate_salt().hex()  # store for encryption
                }
                save_data(stored_data)
                st.success("User registered")
        else:
            st.warning("Both fields required")

# --- Login ---
elif choice == "Login":
    st.subheader("Please login")
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")

    if st.button('Login'):
        user = stored_data.get(username)
        if user and verify_password(password, user["password"]["hash"], user["password"]["salt"]):
            st.session_state.authenticated_user = username
            st.success("Login successful")
        else:
            st.warning("Invalid username or password")

# --- Store Data ---
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        key = st.text_input("Enter secret key")
        text = st.text_area("Enter text to encrypt")
        if st.button("Encrypt & Store"):
            if key and text:
                username = st.session_state.authenticated_user
                salt = bytes.fromhex(stored_data[username]["encryption_salt"])
                encrypted = encrypt_text(text, key, salt)
                stored_data[username]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and stored")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        key = st.text_input("Enter secret key to decrypt")
        if st.button("Decrypt All"):
            username = st.session_state.authenticated_user
            salt = bytes.fromhex(stored_data[username]["encryption_salt"])
            for i, enc in enumerate(stored_data[username]["data"]):
                decrypted = decrypt_text(enc, key, salt)
                st.text(f"{i + 1}. {decrypted if decrypted else '🔒 Decryption failed'}")

# --- Delete Data ---
elif choice == "Delete Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        if st.button("Delete All My Data"):
            stored_data[st.session_state.authenticated_user]["data"] = []
            save_data(stored_data)
            st.success("All data deleted")


    


