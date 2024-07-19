import atexit
from io import BytesIO
import sqlite3
from flask import render_template, request, redirect, url_for, send_file, session, flash
import os
from datetime import datetime, timedelta
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from .form import EncryptionForm, UploadImagePath, DecryptionForm
from application import app

upload_image_path = UploadImagePath()
secret_key = secrets.token_hex(16)
print("Generated Secret Key:", secret_key)
app.secret_key = secret_key

# Database creation functions
def create_files_db():
    conn = sqlite3.connect('files.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            file_data BLOB NOT NULL,
            file_type TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

def create_encrypted_files_db():
    conn = sqlite3.connect('encrypted_files.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            file_type TEXT NOT NULL,
            encryption_key TEXT NOT NULL UNIQUE,
            timestamp DATETIME NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

def create_decrypted_files_db():
    conn = sqlite3.connect('decrypted_files.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS decrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            decrypted_data BLOB NOT NULL,
            file_type TEXT NOT NULL,
            decryption_key TEXT NOT NULL,
            timestamp DATETIME NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

create_files_db()
create_encrypted_files_db()
create_decrypted_files_db()

# Routes
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST", "GET"])
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        
        try:
            file_data = file.read()
            file_name = file.filename
            file_type = file.filename.split('.')[-1]
            
            with sqlite3.connect('files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO files (file_name, file_data, file_type) VALUES (?, ?, ?)
                ''', (file_name, file_data, file_type))
                conn.commit()
                file_id = cursor.lastrowid  # Get the ID of the newly inserted row
            
            # Store file_name and file_id in session
            session['file_name'] = file_name
            session['file_id'] = file_id
            flash("File saved successfully")
        except Exception as e:
            flash(f"Error saving file: {e}")
            return redirect(request.url)
        return redirect(url_for("upload"))
    
    return render_template("index.html")

@app.route("/encryption", methods=["GET", "POST"])
def encryption():
    form = EncryptionForm()
    error_message = None
    success = False
    download_file = None

    if request.method == "POST" and form.validate_on_submit():
        encryption_key = bytes.fromhex(request.form.get("encryption_key")) 
        file_name = session.get('file_name')
        file_id = session.get('file_id')

        if not file_name or not file_id:
            return "No file information in session", 400
        
        try:
            with sqlite3.connect('files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_data, file_type FROM files WHERE id = ? AND file_name = ?
                ''', (file_id, file_name))
                result = cursor.fetchone()

            if not result:
                raise ValueError("File not found")

            file_data, file_type = result
            temp_filepath = f"temp_file.{file_type}"
            
            with open(temp_filepath, 'wb') as f:
                f.write(file_data)

            if file_type in ['jpg', 'jpeg', 'png']:
                encrypt_image(temp_filepath, encryption_key)
            elif file_type == 'pdf':
                encrypt_pdf(temp_filepath, encryption_key)
            elif file_type in ['mp4', 'avi']:
                encrypt_video(temp_filepath, encryption_key)
            elif file_type in ['doc', 'docx']:
                encrypt_doc(temp_filepath, encryption_key)
            elif file_type in ['ppt', 'pptx']:
                encrypt_ppt(temp_filepath, encryption_key)
            elif file_type in ['txt']:
                encrypt_text(temp_filepath, encryption_key)
            elif file_type in ['py', 'js', 'html', 'css', 'c', 'cpp','java','ipynb']:
                encrypt_code(temp_filepath, encryption_key)
            else:
                raise ValueError("Unsupported file type")
            
            with open(temp_filepath, 'rb') as f:
                encrypted_data = f.read()

            os.remove(temp_filepath)

            with sqlite3.connect('encrypted_files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO encrypted_files (file_name, encrypted_data, file_type, encryption_key, timestamp) VALUES (?, ?, ?, ?, ?)
                ''', (file_name, encrypted_data, file_type, request.form.get("encryption_key"), datetime.now()))
                conn.commit()

            with sqlite3.connect('files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM files WHERE id = ? AND file_name = ?
                ''', (file_id, file_name))
                conn.commit()

            success = True
            download_file = request.form.get("encryption_key")

        except Exception as e:
            error_message = f"Encryption error: {str(e)}"
            return render_template("encryption.html", form=form, error_message=error_message, error=True)

    return render_template("encryption.html", form=form, success=success, download_file=download_file, error_message=error_message)

@app.route("/decryption", methods=["GET", "POST"])
def decryption():
    form = DecryptionForm()
    error_message = None
    success = False
    download_file = None

    if request.method == "POST" and form.validate_on_submit():
        key_hex = request.form.get("decryption_key")
        try:
            key = bytes.fromhex(key_hex)
            
            with sqlite3.connect('encrypted_files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_name, encrypted_data, file_type FROM encrypted_files WHERE encryption_key = ?
                ''', (key_hex,))
                result = cursor.fetchone()

            if not result:
                raise ValueError("File not found")

            file_name, encrypted_data, file_type = result
            encrypted_file_io = BytesIO(encrypted_data)
            encrypted_data_bytes = encrypted_file_io.read()

            if file_type in ['jpg', 'jpeg', 'png']:
                decrypted_data = decrypt_image(encrypted_data_bytes, key)
            elif file_type == 'pdf':
                decrypted_data = decrypt_pdf(encrypted_data_bytes, key)
            elif file_type in ['mp4', 'avi']:
                decrypted_data = decrypt_video(encrypted_data_bytes, key)
            elif file_type in ['doc', 'docx']:
                decrypted_data = decrypt_doc(encrypted_data_bytes, key)
            elif file_type in ['ppt', 'pptx']:
                decrypted_data = decrypt_ppt(encrypted_data_bytes, key)
            elif file_type in ['txt']:
                decrypted_data = decrypt_text(encrypted_data_bytes, key)
            elif file_type in ['py', 'js', 'html', 'css', 'c', 'cpp','java','ipynb']:
                decrypted_data = decrypt_code(encrypted_data_bytes, key)
            else:
                raise ValueError("Unsupported file type")


            with sqlite3.connect('decrypted_files.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO decrypted_files (file_name, decrypted_data, file_type, decryption_key, timestamp) VALUES (?, ?, ?, ?, ?)
                ''', (file_name, decrypted_data, file_type, key_hex, datetime.now()))
                conn.commit()

            success = True
            download_file = key_hex

        except Exception as e:
            error_message = f"Decryption error: {str(e)}"
            print(error_message)
            return render_template("decryption.html", form=form, error_message=error_message, error=True)

    return render_template("decryption.html", form=form, success=success, download_file=download_file, error_message=error_message)




@app.route('/encryption_download/<key>')
def encryption_download(key):
    try:
        with sqlite3.connect('encrypted_files.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_name, encrypted_data, file_type, timestamp FROM encrypted_files WHERE encryption_key = ?
            ''', (key,))
            result = cursor.fetchone()

        if not result:
            return "File not found", 404

        file_name, file_data, file_type, timestamp = result

        timestamp_format = '%Y-%m-%d %H:%M:%S.%f'
        file_timestamp = datetime.strptime(timestamp, timestamp_format)

        if datetime.now() > file_timestamp + timedelta(minutes=10):
            return render_template("encryption.html", form=EncryptionForm() ,error_message="File download time has expired",success=False, error=True)

        file_io = BytesIO(file_data)
        file_io.seek(0)

        return send_file(file_io, as_attachment=True, download_name=f"{file_name}.{file_type}")

    except Exception as e:
        return str(e), 500

@app.route('/decryption_download/<key>')
def decryption_download(key):
    try:
        with sqlite3.connect('decrypted_files.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_name, decrypted_data, file_type, timestamp FROM decrypted_files WHERE decryption_key = ?
            ''', (key,))
            result = cursor.fetchone()

        if not result:
            return "File not found", 404

        file_name, file_data, file_type, timestamp = result

        timestamp_format = '%Y-%m-%d %H:%M:%S.%f'
        file_timestamp = datetime.strptime(timestamp, timestamp_format)

        if datetime.now() > file_timestamp + timedelta(minutes=10):
            return render_template("decryption.html", form=DecryptionForm() ,error_message="File download time has expired",success=False, error=True)

        file_io = BytesIO(file_data)
        file_io.seek(0)

        return send_file(file_io, as_attachment=True, download_name=f"{file_name}.{file_type}")

    except Exception as e:
        return f"Error: {str(e)}", 500



def encrypt_image(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)


def encrypt_pdf(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def encrypt_video(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)


def encrypt_doc(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def encrypt_text(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def encrypt_code(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def encrypt_ppt(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(filepath, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def decrypt_image(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_pdf(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_video(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_doc(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_ppt(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_code(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_text(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(pad(key, AES.block_size), AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

from apscheduler.schedulers.background import BackgroundScheduler
import os

# Function to delete expired files from the database
def delete_expired_files():
    try:
        now = datetime.now()
        timestamp_format = '%Y-%m-%d %H:%M:%S.%f'

        with sqlite3.connect('encrypted_files.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, file_name, file_type, timestamp FROM encrypted_files
            ''')
            files = cursor.fetchall()

        for file in files:
            file_id, file_name, file_type, timestamp = file
            file_timestamp = datetime.strptime(timestamp, timestamp_format)
            if now > file_timestamp + timedelta(minutes=10):
                with sqlite3.connect('encrypted_files.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        DELETE FROM encrypted_files WHERE id = ?
                    ''', (file_id,))
                    conn.commit()
                print(f"Deleted expired file: {file_name}.{file_type}")
                with sqlite3.connect('decrypted_files.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        DELETE FROM decrypted_files WHERE id = ?
                    ''', (file_id,))
                    conn.commit()
                print(f"Deleted expired file: {file_name}.{file_type}")

    except Exception as e:
        print(f"Error deleting expired files: {str(e)}")


scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_expired_files, trigger="interval", minutes=10)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())


