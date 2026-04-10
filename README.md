

**One-time setup:**

1. Install the two dependencies by running `pip install cryptography argon2-cffi` in your terminal.
2. Download `secure_vault.py` and put it somewhere convenient, like your Downloads folder.
3. Open a terminal in that folder and run `python secure_vault.py`.

**Creating your vault:**

4. The menu appears. Press `1` to initialize a new vault.
5. Type a master password (minimum 8 characters) and confirm it.
6. The system takes about a second to derive your key — this slowness is intentional security. A `vault/` folder is created in the same directory.

**Storing a file:**

7. Press `2` to store a file.
8. Type the path to the file you want to protect, like `testfile.bin` if it's in the same folder, or the full path like `C:\Users\You\Downloads\testfile.bin`.
9. The file gets chunked, encrypted, and saved as something like `vault/files/a3f8c1d2.vault`. You'll see how long it took and a confirmation.

**Listing your files:**

10. Press `3` to see all stored files — shows the original name, size, and when it was stored.

**Retrieving a file:**

11. Press `4` and enter the file ID shown in the list (the 8-character hex code like `a3f8c1d2`).
12. Choose an output directory or just press Enter for the current folder.
13. The file is integrity-checked, decrypted, and saved with its original filename.

**Locking and exiting:**

14. Press `7` to lock the vault — your master key is wiped from memory.
15. Press `0` to exit entirely.

**Coming back later:**

16. Run `python secure_vault.py` again.
17. Press `1` to unlock, enter your password, and you're back in with access to all your files.

That's it — the vault folder persists between sessions, so your encrypted files are always there waiting for your password.
