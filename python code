from flask import Flask, request, render_template, redirect, session
import sqlite3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

app = Flask(_name_)
app.secret_key = 'your_secret_key_here'

# Encryption keys
AES_KEY = os.urandom(32)  # 32 bytes for AES-256
TDE_KEY = os.urandom(24)   # 24 bytes for Triple DES
BACKEND = default_backend()

# AES Encryption Functions (as in your original code)
def encrypt_aes(text):
    iv1 = os.urandom(16)
    cipher1 = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv1), backend=BACKEND)
    encryptor1 = cipher1.encryptor()
    encrypted1 = encryptor1.update(text.encode()) + encryptor1.finalize()

    iv2 = os.urandom(16)
    cipher2 = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv2), backend=BACKEND)
    encryptor2 = cipher2.encryptor()
    encrypted2 = encryptor2.update(encrypted1) + encryptor2.finalize()

    return base64.b64encode(iv1 + iv2 + encrypted2).decode()

def decrypt_aes(encoded):
    data = base64.b64decode(encoded.encode())
    iv1 = data[:16]
    iv2 = data[16:32]
    encrypted2 = data[32:]

    cipher2 = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv2), backend=BACKEND)
    decryptor2 = cipher2.decryptor()
    decrypted1 = decryptor2.update(encrypted2) + decryptor2.finalize()

    cipher1 = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv1), backend=BACKEND)
    decryptor1 = cipher1.decryptor()
    decrypted_text = decryptor1.update(decrypted1) + decryptor1.finalize()

    return decrypted_text.decode()

# Triple DES (TDE) Encryption Functions
def encrypt_tde(text):
    # Triple DES requires 8-byte IV for CBC mode
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(TDE_KEY), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    
    # Pad the data to be a multiple of 8 bytes (Triple DES block size)
    pad_length = 8 - (len(text) % 8)
    padded_text = text.encode() + bytes([pad_length] * pad_length)
    
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_tde(encoded):
    data = base64.b64decode(encoded.encode())
    iv = data[:8]
    encrypted = data[8:]
    
    cipher = Cipher(algorithms.TripleDES(TDE_KEY), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    
    # Remove padding
    pad_length = decrypted_padded[-1]
    decrypted_text = decrypted_padded[:-pad_length]
    return decrypted_text.decode()

# Combined Encryption (AES + TDE)
def encrypt_combined(text):
    # First encrypt with AES
    aes_encrypted = encrypt_aes(text)
    # Then encrypt the AES result with TDE
    return encrypt_tde(aes_encrypted)

def decrypt_combined(encoded):
    # First decrypt with TDE
    tde_decrypted = decrypt_tde(encoded)
    # Then decrypt the result with AES
    return decrypt_aes(tde_decrypted)

# Initialize DB
def init_db():
    with sqlite3.connect('database.db') as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)')

@app.route('/')
def home():
    if 'username' in session:
        return f"Welcome {session['username']}! <a href='/logout'>Logout</a>"
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        return '''
            <script>
                alert("Passwords do not match.");
                window.location.href = "/";
            </script>
        '''

    # Using combined encryption (AES + TDE)
    encrypted_password = encrypt_combined(password)

    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
        return '''
            <script>
                alert("User registered successfully!");
                window.location.href = "/login";
            </script>
        '''
    except sqlite3.IntegrityError:
        return '''
            <script>
                alert("Account already exists! Try another email.");
                window.location.href = "/";
            </script>
        '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = request.form['password']

    with sqlite3.connect('database.db') as conn:
        cursor = conn.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

    if result:
        try:
            # Using combined decryption (TDE + AES)
            decrypted_password = decrypt_combined(result[0])
            if password == decrypted_password:
                session['username'] = username
                return '''
                    <script>
                        alert("Login successful!");
                        window.location.href = "/";
                    </script>
                '''
        except Exception as e:
            print(f"Decryption error: {e}")  # Log the error for debugging
            pass  # Ignore decryption errors

    return '''
        <script>
            alert("Invalid credentials. Try again.");
            window.location.href = "/login";
        </script>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if _name_ == '_main_':
    init_db()
    app.run(debug=True)
