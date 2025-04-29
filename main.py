import streamlit as st 
import sqlite3
import hashlib
import os 
from cryptography.fernet import Fernet


KEY_FILE = "Simple_Secure_.key"

def Load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    with open(KEY_FILE, "rb") as f:
        return f.read()
    
cipher = Fernet(Load_key())

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


st.title("Secure Data Encryption App")
menu = ["Store Securely", "Retrieve Securely"]
choice = st.sidebar.selectbox("Select an option", menu)

if choice == "Store Securely":
    st.header("Store Securely")
    label = st.text_input("Label (unique ID): ")
    passkey = st.text_input("Passkey (to protect it):", type="password")
    text = st.text_area("Text to store")
    
    if st.button("Encrypt and Store"):
        if label and passkey and text:
            encrypted_text = encrypt(text)
            hashed_passkey = hash_passkey(passkey)
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            try:
                c.execute('''
                    INSERT INTO vault (label, encrypted_text, passkey) 
                    VALUES (?, ?, ?)
                ''', (label, encrypted_text, hashed_passkey))
                conn.commit()
                st.success("Data stored securely!")
            except sqlite3.IntegrityError:
                st.warning("Label already exists. Updating existing entry.")
                c.execute('''
                    INSERT OR REPLACE INTO vault (label, encrypted_text, passkey) 
                    VALUES (?, ?, ?)
                ''', (label, encrypted_text, hashed_passkey))
                conn.commit()
                st.success("Data updated securely!")
            finally:
                conn.close()
        else:
            st.error("Please fill in all fields.")

elif choice == "Retrieve Securely":
    st.header("Retrieve Securely")
    label = st.text_input("Label (unique ID): ")
    passkey = st.text_input("Passkey (to unlock it):", type="password")
    
    if st.button("Decrypt and Retrieve"):
        if label and passkey:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute('''
                SELECT encrypted_text, passkey FROM vault WHERE label = ?
            ''', (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_passkey = result
                if hash_passkey(passkey) == stored_passkey:
                    decrypted_text = decrypt(encrypted_text)
                    st.text_area("Decrypted Text", value=decrypted_text, height=300)
                else:
                    st.error("Incorrect passkey.")
            else:
                st.error("Label not found.")
        else:
            st.error("Please fill in all fields.")

st.sidebar.text("Developed by [SAIF SOOMRO 🌍]")
