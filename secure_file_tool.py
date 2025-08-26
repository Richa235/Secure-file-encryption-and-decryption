#!/usr/bin/env python3
"""
Secure File Encryption & Decryption (AES‑GCM + scrypt)
- GUI (Tkinter) and CLI in a single file.
- No key files to manage: derives a 256‑bit AES key from your password using scrypt.
- Authenticated encryption (GCM) prevents undetected tampering.
File format:
  MAGIC(4)="SFE1" | SALT(16) | NONCE(12) | CIPHERTEXT | TAG(16)
"""
import os
import sys
from pathlib import Path
from typing import Callable, Optional

# Crypto
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# GUI (import lazily so CLI users don't need Tk on servers without it)
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:
    tk = None
    ttk = None
    filedialog = None
    messagebox = None

MAGIC = b"SFE1"           # includes version 1 in the magic
SALT_LEN = 16
NONCE_LEN = 12            # recommended size for GCM
TAG_LEN = 16
CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks

class CryptoError(Exception):
    pass

def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    # scrypt parameters: strong but fast enough on most machines
    return scrypt(password=password.encode("utf-8"), salt=salt,
                  key_len=32, N=2**15, r=8, p=1)

def encrypt_file(in_path: str, out_path: Optional[str], password: str,
                 delete_original: bool=False,
                 progress_cb: Optional[Callable[[float], None]]=None) -> str:
    """Encrypt file at in_path -> out_path (.enc if None). Returns out_path."""
    in_path = str(in_path)
    if out_path is None:
        out_path = in_path + ".enc"
    if os.path.abspath(in_path) == os.path.abspath(out_path):
        raise ValueError("Output path must be different from input path")
    file_size = os.path.getsize(in_path)
    salt = get_random_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    written = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # header
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)
        # stream encrypt
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = cipher.encrypt(chunk)
            fout.write(ct)
            written += len(chunk)
            if progress_cb:
                progress_cb(min(1.0, written / file_size if file_size else 1.0))
        # trailer: auth tag
        tag = cipher.digest()
        fout.write(tag)

    if delete_original:
        os.remove(in_path)
    return out_path

def decrypt_file(in_path: str, out_path: Optional[str], password: str,
                 progress_cb: Optional[Callable[[float], None]]=None) -> str:
    """Decrypt file at in_path -> out_path (strip .enc or add .dec). Returns out_path."""
    in_path = str(in_path)
    size = os.path.getsize(in_path)
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if size < header_len + TAG_LEN:
        raise CryptoError("File too small or not in expected format")

    if out_path is None:
        if in_path.endswith(".enc"):
            out_path = in_path[:-4]
        else:
            out_path = in_path + ".dec"

    with open(in_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise CryptoError("Bad file format (magic mismatch)")
        salt = fin.read(SALT_LEN)
        nonce = fin.read(NONCE_LEN)
        key = _derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # ciphertext length (everything except header + tag)
        ciphertext_len = size - header_len - TAG_LEN
        remaining = ciphertext_len
        written = 0

        with open(out_path, "wb") as fout:
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                chunk = fin.read(to_read)
                if not chunk:
                    raise CryptoError("Unexpected end of file during decryption")
                pt = cipher.decrypt(chunk)
                fout.write(pt)
                remaining -= len(chunk)
                written += len(chunk)
                if progress_cb:
                    progress_cb(min(1.0, written / ciphertext_len if ciphertext_len else 1.0))
            tag = fin.read(TAG_LEN)
            try:
                cipher.verify(tag)
            except ValueError:
                # remove possibly partial output
                try:
                    fout.close()
                finally:
                    try:
                        os.remove(out_path)
                    except Exception:
                        pass
                raise CryptoError("Decryption failed: wrong password or file corrupted")
    return out_path

# ----------------------------- CLI -----------------------------
def _cli():
    import argparse, getpass
    p = argparse.ArgumentParser(description="Secure File Encryption & Decryption (AES-GCM)")
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--encrypt", "-e", metavar="FILE", help="Encrypt this file")
    g.add_argument("--decrypt", "-d", metavar="FILE", help="Decrypt this file")
    p.add_argument("-o", "--out", metavar="FILE", help="Output file path")
    p.add_argument("-p", "--password", metavar="PASS", help="Password (avoid using on shared terminals)")
    p.add_argument("--delete-original", action="store_true", help="Delete the input file after successful encryption")
    args = p.parse_args()

    if not args.encrypt and not args.decrypt:
        return False  # fall back to GUI

    mode = "encrypt" if args.encrypt else "decrypt"
    in_path = args.encrypt or args.decrypt
    if not os.path.exists(in_path):
        print(f"[!] File not found: {in_path}", file=sys.stderr)
        sys.exit(2)
    password = args.password or getpass.getpass("Password: ")
    try:
        if mode == "encrypt":
            outp = encrypt_file(in_path, args.out, password, delete_original=args.delete_original)
            print(f"[+] Encrypted -> {outp}")
        else:
            outp = decrypt_file(in_path, args.out, password)
            print(f"[+] Decrypted -> {outp}")
    except (CryptoError, ValueError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    return True

# ----------------------------- GUI -----------------------------
def _launch_gui():
    if tk is None:
        print("Tkinter not available. Use the CLI mode with --help.", file=sys.stderr)
        sys.exit(2)

    root = tk.Tk()
    root.title("Secure File Encryptor (AES‑GCM)")
    root.geometry("560x340")
    root.resizable(False, False)

    operation = tk.StringVar(value="encrypt")
    file_var = tk.StringVar()
    password_var = tk.StringVar()
    show_pw = tk.BooleanVar(value=False)
    delete_var = tk.BooleanVar(value=False)

    def choose_file():
        if operation.get() == "encrypt":
            path = filedialog.askopenfilename(title="Choose file to encrypt")
        else:
            path = filedialog.askopenfilename(title="Choose file to decrypt")
        if path:
            file_var.set(path)

    def update_pw_visibility():
        entry_pw.config(show="" if show_pw.get() else "•")

    progress = tk.DoubleVar(value=0.0)
    status_var = tk.StringVar(value="Idle")

    def progress_cb(v):
        progress.set(v * 100.0)
        root.update_idletasks()

    def start():
        path = file_var.get().strip()
        pw = password_var.get()
        if not path:
            messagebox.showwarning("Input required", "Please choose a file.")
            return
        if not pw:
            messagebox.showwarning("Input required", "Please enter a password.")
            return
        try:
            progress.set(0.0)
            status_var.set("Working...")
            root.update_idletasks()
            if operation.get() == "encrypt":
                outp = encrypt_file(path, None, pw, delete_original=delete_var.get(), progress_cb=progress_cb)
                status_var.set(f"Done: {outp}")
                messagebox.showinfo("Success", f"Encrypted to:\n{outp}")
            else:
                outp = decrypt_file(path, None, pw, progress_cb=progress_cb)
                status_var.set(f"Done: {outp}")
                messagebox.showinfo("Success", f"Decrypted to:\n{outp}")
        except CryptoError as e:
            status_var.set("Failed")
            messagebox.showerror("Error", str(e))
        except Exception as e:
            status_var.set("Failed")
            messagebox.showerror("Error", f"Unexpected error: {e}")

    frm = ttk.Frame(root, padding=16)
    frm.pack(fill="both", expand=True)

    # Row 1: Mode
    ttk.Label(frm, text="Mode:").grid(row=0, column=0, sticky="w", pady=(0,8))
    ttk.Radiobutton(frm, text="Encrypt", variable=operation, value="encrypt").grid(row=0, column=1, sticky="w", pady=(0,8))
    ttk.Radiobutton(frm, text="Decrypt", variable=operation, value="decrypt").grid(row=0, column=2, sticky="w", pady=(0,8))

    # Row 2: File
    ttk.Label(frm, text="File:").grid(row=1, column=0, sticky="w")
    ttk.Entry(frm, textvariable=file_var, width=48).grid(row=1, column=1, columnspan=2, sticky="we")
    ttk.Button(frm, text="Browse…", command=choose_file).grid(row=1, column=3, sticky="e")

    # Row 3: Password
    ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w", pady=(8,0))
    entry_pw = ttk.Entry(frm, textvariable=password_var, width=48, show="•")
    entry_pw.grid(row=2, column=1, columnspan=2, sticky="we", pady=(8,0))
    ttk.Checkbutton(frm, text="Show", variable=show_pw, command=update_pw_visibility).grid(row=2, column=3, sticky="w", pady=(8,0))

    # Row 4: Options
    ttk.Checkbutton(frm, text="Delete original after encrypt", variable=delete_var).grid(row=3, column=1, columnspan=3, sticky="w", pady=(8,0))

    # Row 5: Progress
    ttk.Label(frm, text="Progress:").grid(row=4, column=0, sticky="w", pady=(16,0))
    pb = ttk.Progressbar(frm, variable=progress, maximum=100.0)
    pb.grid(row=4, column=1, columnspan=3, sticky="we", pady=(16,0))

    # Row 6: Status + Start button
    ttk.Label(frm, textvariable=status_var).grid(row=5, column=0, columnspan=3, sticky="w", pady=(8,0))
    ttk.Button(frm, text="Start", command=start).grid(row=5, column=3, sticky="e", pady=(8,0))

    for i in range(4):
        frm.columnconfigure(i, weight=1)

    root.mainloop()

if __name__ == "__main__":
    used_cli = _cli()
    if not used_cli:
        _launch_gui()
