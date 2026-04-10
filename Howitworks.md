**When you create a vault:**

1. You pick a master password.
2. The system generates a random 32-byte salt and saves it to disk.
3. Your password and the salt are fed into Argon2id, a deliberately slow function that uses 64MB of RAM and takes about a second. This makes brute-force guessing extremely expensive.
4. Argon2id outputs 512 bits. The first half is hashed with SHA-256 to create a verification hash, which is saved to disk. The second half becomes your master encryption key, which is held only in memory and never written anywhere.

**When you store a file:**

5. A random 256-bit key is generated just for this file.
6. That per-file key is encrypted ("wrapped") using your master key with AES-256-GCM, and the wrapped version is stored in the output file's header.
7. The original file is read in 64KB chunks. Each chunk is encrypted individually with the per-file key, and each encryption produces a 16-byte tamper-detection tag.
8. All the chunk tags are fed into an HMAC-SHA256 to produce a single file-level integrity checksum, which is appended at the end.
9. The encrypted file is saved with a random hex name like `a3f8c1d2.vault`. The original filename is stored in a separate encrypted index file that only your master key can read.
10. The per-file key is zeroed from memory.

**When you retrieve a file:**

11. Your master key unwraps the per-file key from the vault file's header. If the key is wrong or the header was tampered with, this fails immediately.
12. The file-level HMAC is verified to make sure nothing was modified on disk.
13. Each chunk is decrypted one by one, and each chunk's GCM tag is verified. If even a single byte was changed, decryption halts.
14. After all chunks are reassembled, the output file's SHA-256 hash is compared against what was recorded at storage time to confirm a perfect match.
15. The per-file key is zeroed from memory again.

**When you lock the vault or exit:**

16. The master key is overwritten with zeros in memory. No key material remains anywhere — not on disk, not in RAM. The only things on disk are encrypted blobs and a salt plus hash from which your password cannot be recovered.

**Why the two-level key design matters:**

If you change your password, the system only needs to re-wrap each file's small per-file key with the new master key. It doesn't need to re-encrypt any actual file data, so a password change takes under a second even with hundreds of stored files.
