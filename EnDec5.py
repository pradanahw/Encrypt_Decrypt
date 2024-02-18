import tkinter as tk
from tkinter import ttk, filedialog
from ttkthemes import ThemedTk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_hashed_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())
    return salt, hashed_password

def encrypt_file(file_path, password, salt, hashed_password):
    key = generate_key(password, salt)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(salt + ciphertext)

def decrypt_file(encrypted_file_path, password, salt, hashed_password):
    with open(encrypted_file_path, 'rb') as encrypted_file:
        data = encrypted_file.read()

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data[16:]) + decryptor.finalize()

    return plaintext

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)

def create_new_password():
    new_password = entry_new_password.get()

    if not new_password:
        result_label_new_password.config(text="Password baru tidak boleh kosong.", foreground="red")
        return

    # Simpan password baru dengan menghasilkan hashed password dan salt
    new_salt, new_hashed_password = generate_hashed_password(new_password)

    # Simpan salt dan hashed password baru di tempat yang aman (misalnya, di file)
    with open("password_info.txt", 'wb') as password_info_file:
        password_info_file.write(new_salt + b'\n' + new_hashed_password)

    result_label_new_password.config(text="Password baru berhasil dibuat.", foreground="green")

    # Menghapus input setelah tindakan selesai
    entry_new_password.delete(0, tk.END)

def clean_password_info():
    # Membersihkan data pada file password_info.txt
    with open("password_info.txt", 'wb') as password_info_file:
        password_info_file.write(b'')

    result_label_clean_password_info.config(text="Data password lama telah dihapus.", foreground="green")

def process(encrypt_flag):
    password = entry_password.get()
    file_path = entry_file_path.get()

    if not password or not file_path:
        result_label.config(text="Isi password dan pilih file terlebih dahulu.", foreground="red")
        return

    # Baca salt dan hashed password dari file (mungkin Anda ingin melindungi file ini)
    with open("password_info.txt", 'rb') as password_info_file:
        data = password_info_file.read()
    stored_salt = data[:16]
    stored_hashed_password = data[17:]

    # Verifikasi password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=stored_salt,
        length=32,
        backend=default_backend()
    )
    hashed_attempted_password = kdf.derive(password.encode())

    if hashed_attempted_password == stored_hashed_password:
        try:
            if encrypt_flag:
                encrypt_file(file_path, password, stored_salt, stored_hashed_password)
                result_label.config(text="Enkripsi berhasil. File enkripsi tersimpan di " + file_path + '.enc', foreground="green")
            else:
                decrypted_content = decrypt_file(file_path, password, stored_salt, stored_hashed_password)
                original_file_path = file_path[:-4]  # Menghapus ekstensi '.enc' dari nama file
                with open(original_file_path, 'wb') as original_file:
                    original_file.write(decrypted_content)
                result_label.config(text="Dekripsi berhasil. File didekripsi dan tersimpan di " + original_file_path, foreground="green")
        except Exception as e:
            result_label.config(text="Proses gagal. Pastikan file dan password benar.", foreground="red")
    else:
        result_label.config(text="Password salah.", foreground="red")

# Buat ThemedTk agar dapat menggunakan tema dari ttkthemes
app = ThemedTk(theme="breeze")
app.title("Enkripsi Dekripsi File")

frame = ttk.Frame(app, padding="20")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Label dan Entry Password
label_password = ttk.Label(frame, text="Password:", font=("Helvetica", 12), foreground="black")
label_password.grid(row=2, column=0, sticky="w", pady=(10, 0))
entry_password = ttk.Entry(frame, show="*", font=("Helvetica", 12))
entry_password.grid(row=2, column=1, pady=(10, 0), padx=(0, 10))

# Label, Entry, dan Tombol Browse File
label_file_path = ttk.Label(frame, text="Path File:", font=("Helvetica", 12), foreground="black")
label_file_path.grid(row=3, column=0, sticky="w", pady=(10, 0))
entry_file_path = ttk.Entry(frame, font=("Helvetica", 12))
entry_file_path.grid(row=3, column=1, pady=(10, 0), padx=(0, 10))
button_browse = ttk.Button(frame, text="Browse", command=lambda: browse_file(entry_file_path), cursor="hand2", style="TButton.Browse.TButton")
button_browse.grid(row=3, column=2, pady=(10, 0))

# Tombol Enkripsi dan Dekripsi
button_encrypt = ttk.Button(frame, text="Enkripsi", command=lambda: process(True), cursor="hand2", compound=tk.LEFT, style="TButton.Encrypt.TButton")
button_encrypt.grid(row=4, column=0, pady=(10, 0))
button_decrypt = ttk.Button(frame, text="Dekripsi", command=lambda: process(False), cursor="hand2", compound=tk.LEFT, style="TButton.Decrypt.TButton")
button_decrypt.grid(row=4, column=1, pady=(10, 0))

# Tombol Membersihkan Data Password Lama
button_clean_password_info = ttk.Button(frame, text="Hapus Data Password Lama", command=clean_password_info, cursor="hand2", style="TButton.CleanPasswordInfo.TButton")
button_clean_password_info.grid(row=5, column=0, columnspan=3, pady=(10, 0))
result_label_clean_password_info = ttk.Label(frame, text="", font=("Helvetica", 12))
result_label_clean_password_info.grid(row=6, column=0, columnspan=3, pady=(0, 10))

# Label Hasil Operasi
result_label = ttk.Label(frame, text="", font=("Helvetica", 12))
result_label.grid(row=7, column=0, columnspan=3, pady=(0, 10))

# Label, Entry, dan Tombol untuk Membuat Password Baru
label_new_password = ttk.Label(frame, text="Password Baru:", font=("Helvetica", 12), foreground="black")
label_new_password.grid(row=8, column=0, sticky="w", pady=(10, 0))
entry_new_password = ttk.Entry(frame, show="*", font=("Helvetica", 12))
entry_new_password.grid(row=8, column=1, pady=(10, 0), padx=(0, 10))
button_create_new_password = ttk.Button(frame, text="Buat Password Baru", command=create_new_password, cursor="hand2", style="TButton.NewPassword.TButton")
button_create_new_password.grid(row=9, column=0, columnspan=3, pady=(10, 0))
result_label_new_password = ttk.Label(frame, text="", font=("Helvetica", 12))
result_label_new_password.grid(row=10, column=0, columnspan=3, pady=(0, 10))

# Menonaktifkan tombol maximize
app.resizable(False, False)

app.mainloop()
