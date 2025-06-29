import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate and cache a persistent encryption key
@st.cache_resource
def get_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = get_cipher()

# Session state initialization
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # key: encrypted_text, value: {"encrypted_text", "passkey"}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text with passkey validation
def decrypt_data(encrypted_text, passkey):
    hashed_pass = hash_passkey(passkey)
    data = st.session_state.stored_data.get(encrypted_text)

    if data and data["passkey"] == hashed_pass:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Reauthorize user
def reauthorize():
    st.session_state.authorized = False

# ----------------- UI -----------------

st.title("🔐 Secure Data Storage & Retrieval")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# 1️⃣ Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("""
    Securely store and retrieve encrypted data using passkeys.
    1. Data is encrypted with **Fernet symmetric encryption**.
    2. Passkeys are hashed using **SHA-256**.
    3. 3 failed attempts locks decryption until login.
    """)

# 2️⃣ Store Data Page
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_pass
            }
            st.success("✅ Data stored securely.")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required.")

# 3️⃣ Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")

    if not st.session_state.authorized:
        st.warning("🔐 Reauthorization required.")
        st.stop()

    encrypted_input = st.text_area("Enter Encrypted Data:")
    passkey_input = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)

            if result:
                st.success("✅ Decryption successful.")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Redirecting to login.")
                    reauthorize()
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

# 4️⃣ Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful.")
            st.info("Now go back to the Retrieve Data tab.")
        else:
            st.error("❌ Incorrect master password.")
