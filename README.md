# Secure File Encryption & Decryption (Python, AES‑GCM)

A minimal, production‑ready tool to encrypt and decrypt files using AES‑256‑GCM with a key derived from your password via **scrypt**. It includes both a Tkinter GUI and a CLI in a single file.

## Why this design?
- **PyCryptodome** (not the deprecated PyCrypto) provides modern ciphers.
- **AES‑GCM** gives confidentiality *and* integrity (prevents silent corruption).
- **scrypt** turns your password into a strong 256‑bit key with salt.

---

## 1) Requirements

- Python 3.8+
- VS Code + the “Python” extension
- Pip to install dependencies

> **Tkinter note:**  
> - Windows/macOS Python builds include Tkinter.  
> - On Ubuntu/Debian you may need: `sudo apt-get install python3-tk`

---

## 2) Quick start in VS Code

1. **Open folder** `secure-file-encryptor/` in VS Code.
2. Create a virtual environment:
   ```bash
   # Windows
   py -3 -m venv .venv
   .venv\Scripts\activate
   # macOS/Linux
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the app:**
   - GUI: Press **F5** in VS Code (or `python secure_file_tool.py`)
   - CLI help: `python secure_file_tool.py -h`

The first run will ask you to select a Python interpreter. Choose the one from `.venv`.

---

## 3) How to use

### GUI
1. Choose **Encrypt** or **Decrypt**.
2. Click **Browse** and select your file.
3. Enter a password (you must remember it!).
4. Click **Start**.
   - Encrypted files end with `.enc`.
   - Decrypting `X.enc` restores to `X` (or `X.dec` if the original name didn’t end with `.enc`).

### CLI
```bash
# Encrypt
python secure_file_tool.py -e /path/to/file.txt -p "yourPassword"
# Decrypt
python secure_file_tool.py -d /path/to/file.txt.enc -p "yourPassword"
# Choose output path
python secure_file_tool.py -e in.bin -o out.bin.enc
# Delete original after successful encrypt
python secure_file_tool.py -e secret.pdf --delete-original
```

---

## 4) How it works (file format)

```
MAGIC(4)="SFE1" | SALT(16) | NONCE(12) | CIPHERTEXT | TAG(16)
```
- 16‑byte random **salt** feeds scrypt to derive a 256‑bit AES key.
- 12‑byte **nonce** is generated per file.
- **TAG** (GCM authentication tag) is verified on decryption — if wrong, you’ll get an error instead of corrupted output.

---

## 5) Security tips

- Use a **strong password** and store it in a password manager.
- Losing/forgetting the password means the data is **unrecoverable** by design.
- Keep backups of your encrypted files. Corruption cannot be “half‑decrypted”.
- If you share the `.enc` file, share the password via a **separate secure channel**.

---

## 6) Make a standalone executable (optional)

You can package the app as a single file with PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed secure_file_tool.py
# The binary appears in the "dist" folder.
```

---

## 7) Troubleshooting

- **`ModuleNotFoundError: Crypto`** → Dependency missing. Run `pip install -r requirements.txt` in the *activated* venv.
- **Tkinter not found on Linux** → `sudo apt-get install python3-tk`
- **"Decryption failed: wrong password or file corrupted"** → Either the password is incorrect, or the file was modified/damaged.
