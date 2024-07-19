# Encryptify: File Encryption and Decryption Web Application

**Encryptify** is a web application that allows users to securely encrypt and decrypt various file types such as images, PDFs, and videos using AES encryption. Users can upload files, specify a unique key for encryption, and later use the same key for decryption. The application ensures that sensitive files are securely handled and stored.

## Features

- **File encryption:** Encrypt files using a unique key provided by the user.
- **File decryption:** Decrypt files using the unique key provided during encryption.
- **Multiple file types supported:** Encrypt and decrypt images, PDFs, videos, and more.
- **Secure storage:** Files are securely stored in the database with encrypted content.
- **Download timer:** Limit the download of encrypted files to under 10 minutes.

## Live Demo

Access the application at [https://encryptify.onrender.com](https://encryptify.onrender.com).

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- PyCryptodome
- Flask-Dropzone
- Flask-WTF

## Understanding AES Algorithm

**Advanced Encryption Standard (AES)** is a symmetric encryption algorithm widely used for securing data. Here’s a brief overview of how AES works:

(![AES Algorithm](https://github.com/user-attachments/assets/de74aa53-aef0-4a07-9d80-ea791d543734))


### Steps in AES Encryption:

1. **Key Expansion:**
   - The encryption key is expanded into multiple key schedules, which are used in different rounds of the encryption process.

2. **Initial Round:**
   - **AddRoundKey:** The plaintext is XORed with the first round key.

3. **Rounds:**
   - **SubBytes:** Each byte of the data is substituted with a corresponding byte from a fixed substitution table (S-Box).
   - **ShiftRows:** Rows of the data matrix are shifted by varying offsets to diffuse the data.
   - **MixColumns:** Columns of the data matrix are mixed to further obscure the data.
   - **AddRoundKey:** The data is XORed with the round key.

4. **Final Round:**
   - **SubBytes:** Byte substitution is applied.
   - **ShiftRows:** Rows are shifted.
   - **AddRoundKey:** The final round key is XORed with the data to produce the ciphertext.

### Key Features of AES:

- **Symmetric Key Encryption:** Uses the same key for both encryption and decryption.
- **Block Cipher:** Encrypts data in fixed-size blocks (128 bits).
- **Variable Key Lengths:** Supports 128, 192, or 256-bit keys.
- **High Security:** Widely recognized for its robustness and is used globally to protect sensitive information.

In Encryptify, AES ensures that your files are encrypted securely and can only be decrypted by those who possess the correct key.

## Setup Instructions

1. Clone the repository.

    ```bash
    git clone https://github.com/kajalrawat3603/Encryptify.git
    ```

2. Navigate to the project directory.

    ```bash
    cd Encryptify
    ```

3. Install the required dependencies using pip.

    ```bash
    pip install -r requirements.txt
    ```

4. Run the application.

    ```bash
    python run.py
    ```

5. Access the application in your web browser at [http://localhost:5000](http://localhost:5000).

## Usage

1. Upload a file you want to encrypt.
2. Provide a unique key for encryption.
3. Encrypt the file and download the encrypted version.
4. To decrypt, upload the encrypted file and provide the same unique key.
5. Decrypt the file and download the decrypted version.
6. Ensure to download encrypted files within the specified 10-minute window.
