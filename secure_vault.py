
"""
Secure Local File Storage System (SecureVault)
==============================================
A complete implementation of password-authenticated, AES-256-GCM encrypted
local file storage with chunked streaming for files up to 4GB.

Dependencies:
    pip install cryptography argon2-cffi

Usage:
    python secure_vault.py

Architecture:
    - Authentication: Argon2id KDF → 512-bit master key
    - Encryption: AES-256-GCM with per-file keys, 64KB chunked streaming
    - Integrity: Per-chunk GCM tags + file-level HMAC-SHA256
    - Storage: Opaque .vault files, encrypted metadata index
"""

import os
import sys
import json
import hmac
import struct
import hashlib
import shutil
import getpass
import secrets
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    from argon2.low_level import hash_secret_raw, Type
except ImportError:
    print("Missing dependency: argon2-cffi")
    print("Install with:  pip install argon2-cffi")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Missing dependency: cryptography")
    print("Install with:  pip install cryptography")
    sys.exit(1)


# ─── Constants ────────────────────────────────────────────────────────────────

MAGIC = b"VAUT"
FORMAT_VERSION = 1
CHUNK_SIZE = 65536  # 64 KB
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 32
KEY_SIZE = 32  # 256 bits
MASTER_OUTPUT_SIZE = 64  # 512 bits

# Argon2id parameters
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4

DEFAULT_VAULT_DIR = "vault"


# ─── Cryptographic Primitives ─────────────────────────────────────────────────

def derive_master_key(password: str, salt: bytes, key_file_data: Optional[bytes] = None) -> bytes:
    """Derive 512-bit master key from password using Argon2id."""
    pwd_bytes = password.encode("utf-8")

    if key_file_data is not None:
        key_file_hash = hashlib.sha256(key_file_data).digest()
        pwd_bytes = bytes(a ^ b for a, b in zip(
            pwd_bytes.ljust(len(key_file_hash), b'\x00'),
            key_file_hash.ljust(len(pwd_bytes), b'\x00')
        ))

    master_output = hash_secret_raw(
        secret=pwd_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=MASTER_OUTPUT_SIZE,
        type=Type.ID,
    )
    return master_output


def split_master_key(master_output: bytes) -> tuple:
    """Split 512-bit master output into verification material and encryption key."""
    verification_material = master_output[:32]
    encryption_key = master_output[32:]
    verification_hash = hashlib.sha256(verification_material).digest()
    return verification_hash, encryption_key


def generate_file_key() -> bytes:
    """Generate a random 256-bit per-file key."""
    return secrets.token_bytes(KEY_SIZE)


def wrap_key(plaintext_key: bytes, wrapping_key: bytes) -> tuple:
    """Encrypt a per-file key with the master encryption key. Returns (nonce, ciphertext_with_tag)."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(wrapping_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_key, None)
    return nonce, ciphertext


def unwrap_key(nonce: bytes, ciphertext: bytes, wrapping_key: bytes) -> bytes:
    """Decrypt a wrapped per-file key."""
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def build_chunk_nonce(file_id_bytes: bytes, counter: int) -> bytes:
    """Build a 12-byte nonce: 4-byte file_id + 4-byte reserved + 4-byte counter."""
    return file_id_bytes[:4].ljust(4, b'\x00') + b'\x00\x00\x00\x00' + struct.pack(">I", counter)


def secure_zero(data: bytearray):
    """Overwrite a bytearray with zeros (best-effort memory clearing)."""
    for i in range(len(data)):
        data[i] = 0


# ─── Encrypted Index ──────────────────────────────────────────────────────────

class EncryptedIndex:
    """Manages the encrypted file metadata index."""

    def __init__(self, index_path: Path, master_key: bytes):
        self.path = index_path
        self.master_key = master_key
        self.entries = {}

    def load(self):
        """Load and decrypt the index from disk."""
        if not self.path.exists():
            self.entries = {}
            return

        raw = self.path.read_bytes()
        if len(raw) < NONCE_SIZE + TAG_SIZE:
            self.entries = {}
            return

        nonce = raw[:NONCE_SIZE]
        ciphertext = raw[NONCE_SIZE:]
        aesgcm = AESGCM(self.master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        self.entries = json.loads(plaintext.decode("utf-8"))

    def save(self):
        """Encrypt and write the index to disk."""
        plaintext = json.dumps(self.entries, indent=2).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        self.path.write_bytes(nonce + ciphertext)

    def add_entry(self, file_id: str, original_name: str, original_size: int, chunk_count: int, plaintext_hash: str):
        """Add a file entry to the index."""
        self.entries[file_id] = {
            "original_name": original_name,
            "original_size": original_size,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "chunk_count": chunk_count,
            "sha256_plaintext": plaintext_hash,
        }
        self.save()

    def remove_entry(self, file_id: str):
        """Remove a file entry from the index."""
        if file_id in self.entries:
            del self.entries[file_id]
            self.save()

    def list_entries(self) -> dict:
        return self.entries


# ─── File Encryption / Decryption ─────────────────────────────────────────────

def encrypt_file(source_path: Path, vault_file_path: Path, master_key: bytes) -> dict:
    """
    Encrypt a file using chunked AES-256-GCM with a per-file key.
    Returns metadata dict with file_id, chunk_count, plaintext_hash.
    """
    file_key = generate_file_key()
    file_id = secrets.token_hex(4)
    file_id_bytes = bytes.fromhex(file_id)
    original_size = source_path.stat().st_size

    # Wrap the per-file key with master key
    wrap_nonce, wrapped_key = wrap_key(file_key, master_key)

    # Prepare HMAC for file-level integrity
    hmac_obj = hmac.new(file_key, digestmod=hashlib.sha256)

    # SHA-256 of plaintext for post-decryption verification
    plaintext_hasher = hashlib.sha256()

    aesgcm = AESGCM(file_key)
    chunk_counter = 0

    with open(source_path, "rb") as fin, open(vault_file_path, "wb") as fout:
        # ── Write header ──
        fout.write(MAGIC)                                          # 4B magic
        fout.write(struct.pack(">H", FORMAT_VERSION))              # 2B version
        fout.write(wrap_nonce)                                     # 12B wrapping nonce
        fout.write(wrapped_key)                                    # 48B wrapped key (32 + 16 tag)
        fout.write(struct.pack(">Q", original_size))               # 8B original size
        fout.write(struct.pack(">I", CHUNK_SIZE))                  # 4B chunk size

        # ── Encrypt chunks ──
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            plaintext_hasher.update(chunk)
            nonce = build_chunk_nonce(file_id_bytes, chunk_counter)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)

            # ciphertext includes the GCM tag appended by the library
            # Extract the tag (last 16 bytes) for HMAC
            tag = ciphertext[-TAG_SIZE:]
            hmac_obj.update(tag)

            fout.write(nonce)        # 12B nonce
            fout.write(ciphertext)   # chunk ciphertext + 16B tag

            chunk_counter += 1

        # ── Write footer ──
        file_hmac = hmac_obj.digest()
        fout.write(file_hmac)  # 32B HMAC

    # Zero the file key
    file_key_arr = bytearray(file_key)
    secure_zero(file_key_arr)

    return {
        "file_id": file_id,
        "chunk_count": chunk_counter,
        "plaintext_hash": plaintext_hasher.hexdigest(),
        "original_size": original_size,
    }


def decrypt_file(vault_file_path: Path, output_path: Path, master_key: bytes, expected_hash: Optional[str] = None) -> bool:
    """
    Decrypt a .vault file using chunked AES-256-GCM.
    Returns True on success, raises on integrity failure.
    """
    with open(vault_file_path, "rb") as fin:
        # ── Read header ──
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError("Not a valid .vault file (bad magic number)")

        version = struct.unpack(">H", fin.read(2))[0]
        if version != FORMAT_VERSION:
            raise ValueError(f"Unsupported format version: {version}")

        wrap_nonce = fin.read(NONCE_SIZE)           # 12B
        wrapped_key = fin.read(KEY_SIZE + TAG_SIZE)  # 48B
        original_size = struct.unpack(">Q", fin.read(8))[0]
        chunk_size = struct.unpack(">I", fin.read(4))[0]

        # ── Unwrap per-file key ──
        try:
            file_key = unwrap_key(wrap_nonce, wrapped_key, master_key)
        except Exception:
            raise PermissionError("Failed to unwrap file key — wrong master key or tampered header")

        aesgcm = AESGCM(file_key)
        hmac_obj = hmac.new(file_key, digestmod=hashlib.sha256)
        plaintext_hasher = hashlib.sha256()

        # ── Calculate data region ──
        header_size = 4 + 2 + NONCE_SIZE + (KEY_SIZE + TAG_SIZE) + 8 + 4  # = 78 bytes
        file_total_size = vault_file_path.stat().st_size
        hmac_footer_size = 32
        data_region_size = file_total_size - header_size - hmac_footer_size

        # Each encrypted chunk: NONCE_SIZE + chunk_ciphertext_size
        # chunk_ciphertext_size = chunk_plaintext_size + TAG_SIZE
        # For the last chunk, plaintext may be smaller

        # ── First pass: collect tags for HMAC verification ──
        fin.seek(header_size)
        tags = []
        bytes_remaining = data_region_size
        while bytes_remaining > 0:
            nonce = fin.read(NONCE_SIZE)
            bytes_remaining -= NONCE_SIZE

            # Determine ciphertext size for this chunk
            # Full chunks: chunk_size + TAG_SIZE
            # Last chunk might be smaller
            max_ct_size = chunk_size + TAG_SIZE
            ct_size = min(max_ct_size, bytes_remaining)
            ciphertext = fin.read(ct_size)
            bytes_remaining -= ct_size

            tag = ciphertext[-TAG_SIZE:]
            tags.append(tag)
            hmac_obj.update(tag)

        # Read stored HMAC
        stored_hmac = fin.read(32)
        computed_hmac = hmac_obj.digest()

        if not hmac.compare_digest(computed_hmac, stored_hmac):
            file_key_arr = bytearray(file_key)
            secure_zero(file_key_arr)
            raise ValueError("File-level HMAC verification failed — file has been tampered with")

        # ── Second pass: decrypt chunks ──
        fin.seek(header_size)
        bytes_remaining = data_region_size
        chunk_counter = 0

        with open(output_path, "wb") as fout:
            while bytes_remaining > 0:
                nonce = fin.read(NONCE_SIZE)
                bytes_remaining -= NONCE_SIZE

                max_ct_size = chunk_size + TAG_SIZE
                ct_size = min(max_ct_size, bytes_remaining)
                ciphertext = fin.read(ct_size)
                bytes_remaining -= ct_size

                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                except Exception:
                    # Clean up partial output
                    fout.close()
                    output_path.unlink(missing_ok=True)
                    file_key_arr = bytearray(file_key)
                    secure_zero(file_key_arr)
                    raise ValueError(f"Chunk {chunk_counter} GCM tag verification failed — data corrupted")

                plaintext_hasher.update(plaintext)
                fout.write(plaintext)
                chunk_counter += 1

    # Verify plaintext hash if available
    if expected_hash and plaintext_hasher.hexdigest() != expected_hash:
        output_path.unlink(missing_ok=True)
        raise ValueError("Plaintext hash mismatch — decrypted content doesn't match original")

    # Zero file key
    file_key_arr = bytearray(file_key)
    secure_zero(file_key_arr)

    return True


# ─── Vault Manager ────────────────────────────────────────────────────────────

class Vault:
    """Main vault controller managing auth, encryption, and storage."""

    def __init__(self, vault_dir: str = DEFAULT_VAULT_DIR):
        self.vault_dir = Path(vault_dir)
        self.meta_path = self.vault_dir / "vault.meta"
        self.index_path = self.vault_dir / "index.enc"
        self.files_dir = self.vault_dir / "files"
        self.master_key: Optional[bytes] = None
        self.index: Optional[EncryptedIndex] = None

    @property
    def is_initialized(self) -> bool:
        return self.meta_path.exists()

    @property
    def is_unlocked(self) -> bool:
        return self.master_key is not None

    def _load_meta(self) -> dict:
        return json.loads(self.meta_path.read_text())

    def _save_meta(self, meta: dict):
        self.meta_path.write_text(json.dumps(meta, indent=2))

    def initialize(self, password: str):
        """Create a new vault with the given master password."""
        if self.is_initialized:
            raise FileExistsError("Vault already exists at this location")

        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(exist_ok=True)

        salt = secrets.token_bytes(SALT_SIZE)
        master_output = derive_master_key(password, salt)
        verification_hash, encryption_key = split_master_key(master_output)

        meta = {
            "salt": salt.hex(),
            "verification_hash": verification_hash.hex(),
            "argon2_memory": ARGON2_MEMORY_COST,
            "argon2_time": ARGON2_TIME_COST,
            "argon2_parallelism": ARGON2_PARALLELISM,
            "format_version": FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_meta(meta)

        self.master_key = encryption_key
        self.index = EncryptedIndex(self.index_path, self.master_key)
        self.index.save()

    def unlock(self, password: str) -> bool:
        """Authenticate and derive the master encryption key."""
        if not self.is_initialized:
            raise FileNotFoundError("No vault found — initialize one first")

        meta = self._load_meta()
        salt = bytes.fromhex(meta["salt"])
        stored_hash = bytes.fromhex(meta["verification_hash"])

        master_output = derive_master_key(password, salt)
        verification_hash, encryption_key = split_master_key(master_output)

        if not hmac.compare_digest(verification_hash, stored_hash):
            return False

        self.master_key = encryption_key
        self.index = EncryptedIndex(self.index_path, self.master_key)
        self.index.load()
        return True

    def lock(self):
        """Zero the master key and close the session."""
        if self.master_key:
            key_arr = bytearray(self.master_key)
            secure_zero(key_arr)
            self.master_key = None
        self.index = None

    def store_file(self, source_path: str) -> str:
        """Encrypt and store a file in the vault."""
        if not self.is_unlocked:
            raise PermissionError("Vault is locked — authenticate first")

        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        file_size = src.stat().st_size
        if file_size > 4 * 1024 * 1024 * 1024:
            raise ValueError("File exceeds 4GB limit")

        print(f"  Encrypting: {src.name} ({format_size(file_size)})")
        start = time.time()

        result = encrypt_file(src, self.files_dir / "temp.vault", self.master_key)

        vault_filename = f"{result['file_id']}.vault"
        (self.files_dir / "temp.vault").rename(self.files_dir / vault_filename)

        self.index.add_entry(
            file_id=result["file_id"],
            original_name=src.name,
            original_size=result["original_size"],
            chunk_count=result["chunk_count"],
            plaintext_hash=result["plaintext_hash"],
        )

        elapsed = time.time() - start
        print(f"  Stored as {vault_filename} in {elapsed:.2f}s")
        print(f"  Chunks: {result['chunk_count']}, SHA-256: {result['plaintext_hash'][:16]}...")

        return result["file_id"]

    def retrieve_file(self, file_id: str, output_dir: str = ".") -> Path:
        """Decrypt and retrieve a file from the vault."""
        if not self.is_unlocked:
            raise PermissionError("Vault is locked — authenticate first")

        entries = self.index.list_entries()
        if file_id not in entries:
            raise KeyError(f"File ID not found: {file_id}")

        entry = entries[file_id]
        vault_file = self.files_dir / f"{file_id}.vault"
        if not vault_file.exists():
            raise FileNotFoundError(f"Encrypted file missing from disk: {vault_file}")

        output_path = Path(output_dir) / entry["original_name"]

        # Handle name collisions
        if output_path.exists():
            stem = output_path.stem
            suffix = output_path.suffix
            counter = 1
            while output_path.exists():
                output_path = Path(output_dir) / f"{stem}_{counter}{suffix}"
                counter += 1

        print(f"  Decrypting: {entry['original_name']} ({format_size(entry['original_size'])})")
        start = time.time()

        decrypt_file(vault_file, output_path, self.master_key, entry.get("sha256_plaintext"))

        elapsed = time.time() - start
        print(f"  Decrypted to {output_path} in {elapsed:.2f}s")
        print(f"  Integrity verified ✓")

        return output_path

    def delete_file(self, file_id: str):
        """Remove an encrypted file from the vault."""
        if not self.is_unlocked:
            raise PermissionError("Vault is locked — authenticate first")

        entries = self.index.list_entries()
        if file_id not in entries:
            raise KeyError(f"File ID not found: {file_id}")

        vault_file = self.files_dir / f"{file_id}.vault"
        if vault_file.exists():
            # Overwrite before deletion for security
            size = vault_file.stat().st_size
            with open(vault_file, "wb") as f:
                f.write(secrets.token_bytes(min(size, 4096)))
            vault_file.unlink()

        self.index.remove_entry(file_id)
        print(f"  Deleted file {file_id}")

    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change the vault master password, re-wrapping all per-file keys."""
        if not self.is_unlocked:
            raise PermissionError("Vault is locked — authenticate first")

        meta = self._load_meta()
        salt_old = bytes.fromhex(meta["salt"])
        master_old = derive_master_key(old_password, salt_old)
        vh_old, mek_old = split_master_key(master_old)

        if not hmac.compare_digest(vh_old, bytes.fromhex(meta["verification_hash"])):
            return False

        # Derive new master key
        salt_new = secrets.token_bytes(SALT_SIZE)
        master_new = derive_master_key(new_password, salt_new)
        vh_new, mek_new = split_master_key(master_new)

        # Re-wrap every per-file key
        entries = self.index.list_entries()
        for file_id in entries:
            vault_file = self.files_dir / f"{file_id}.vault"
            if not vault_file.exists():
                continue

            data = bytearray(vault_file.read_bytes())

            # Extract wrapped key from header
            offset = 6  # after magic + version
            old_wrap_nonce = bytes(data[offset:offset + NONCE_SIZE])
            offset += NONCE_SIZE
            old_wrapped_key = bytes(data[offset:offset + KEY_SIZE + TAG_SIZE])

            # Unwrap with old key, re-wrap with new key
            file_key = unwrap_key(old_wrap_nonce, old_wrapped_key, mek_old)
            new_wrap_nonce, new_wrapped_key = wrap_key(file_key, mek_new)

            # Write new wrapped key back
            offset = 6
            data[offset:offset + NONCE_SIZE] = new_wrap_nonce
            offset += NONCE_SIZE
            data[offset:offset + KEY_SIZE + TAG_SIZE] = new_wrapped_key

            vault_file.write_bytes(bytes(data))

            # Zero file key
            fk_arr = bytearray(file_key)
            secure_zero(fk_arr)

        # Update meta
        meta["salt"] = salt_new.hex()
        meta["verification_hash"] = vh_new.hex()
        self._save_meta(meta)

        # Re-encrypt index with new key
        self.master_key = mek_new
        self.index.master_key = mek_new
        self.index.save()

        # Zero old key
        old_arr = bytearray(mek_old)
        secure_zero(old_arr)

        print("  Password changed successfully. All file keys re-wrapped.")
        return True

    def list_files(self) -> list:
        """List all stored files."""
        if not self.is_unlocked:
            raise PermissionError("Vault is locked — authenticate first")
        return self.index.list_entries()

    def destroy(self):
        """Permanently destroy the entire vault."""
        if self.vault_dir.exists():
            shutil.rmtree(self.vault_dir)
        self.lock()


# ─── Utilities ────────────────────────────────────────────────────────────────

def format_size(size_bytes: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def print_banner():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║            SecureVault v1.0                      ║")
    print("║   AES-256-GCM · Argon2id · Chunked Streaming    ║")
    print("╚══════════════════════════════════════════════════╝")
    print()


def print_menu(vault: Vault):
    status = "UNLOCKED" if vault.is_unlocked else "LOCKED"
    print(f"\n── Vault: {vault.vault_dir.resolve()}  [{status}] ──")
    if not vault.is_initialized:
        print("  [1] Initialize new vault")
    elif not vault.is_unlocked:
        print("  [1] Unlock vault")
    else:
        print("  [2] Store a file")
        print("  [3] List stored files")
        print("  [4] Retrieve a file")
        print("  [5] Delete a file")
        print("  [6] Change password")
        print("  [7] Lock vault")
    print("  [0] Exit")
    print()


# ─── CLI Application ─────────────────────────────────────────────────────────

def main():
    print_banner()

    vault_dir = DEFAULT_VAULT_DIR
    if len(sys.argv) > 1:
        vault_dir = sys.argv[1]

    vault = Vault(vault_dir)

    while True:
        print_menu(vault)

        try:
            choice = input("  > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Locking vault and exiting...")
            vault.lock()
            break

        if choice == "0":
            print("\n  Locking vault and exiting...")
            vault.lock()
            break

        # ── Initialize or Unlock ──
        elif choice == "1":
            if not vault.is_initialized:
                print("\n  Creating a new vault.\n")
                pw1 = getpass.getpass("  Choose master password: ")
                if len(pw1) < 8:
                    print("  ✗ Password must be at least 8 characters.")
                    continue
                pw2 = getpass.getpass("  Confirm master password: ")
                if pw1 != pw2:
                    print("  ✗ Passwords do not match.")
                    continue

                print("  Deriving master key (this may take a moment)...")
                vault.initialize(pw1)
                print("  ✓ Vault initialized and unlocked.")

            elif not vault.is_unlocked:
                pw = getpass.getpass("\n  Master password: ")
                print("  Deriving key...")
                if vault.unlock(pw):
                    entries = vault.list_files()
                    print(f"  ✓ Vault unlocked. {len(entries)} file(s) stored.")
                else:
                    print("  ✗ Wrong password.")

        # ── Store File ──
        elif choice == "2" and vault.is_unlocked:
            file_path = input("  Path to file: ").strip()
            if not file_path:
                continue
            # Strip surrounding quotes if present
            file_path = file_path.strip("'\"")
            try:
                fid = vault.store_file(file_path)
                print(f"  ✓ File stored with ID: {fid}")
            except Exception as e:
                print(f"  ✗ Error: {e}")

        # ── List Files ──
        elif choice == "3" and vault.is_unlocked:
            entries = vault.list_files()
            if not entries:
                print("\n  Vault is empty.")
            else:
                print(f"\n  {'ID':<12} {'Name':<32} {'Size':<12} {'Stored At'}")
                print(f"  {'─'*12} {'─'*32} {'─'*12} {'─'*24}")
                for fid, meta in entries.items():
                    name = meta["original_name"]
                    if len(name) > 30:
                        name = name[:27] + "..."
                    size = format_size(meta["original_size"])
                    stored = meta["stored_at"][:19].replace("T", " ")
                    print(f"  {fid:<12} {name:<32} {size:<12} {stored}")

        # ── Retrieve File ──
        elif choice == "4" and vault.is_unlocked:
            file_id = input("  File ID to retrieve: ").strip()
            output_dir = input("  Output directory [.]: ").strip() or "."
            try:
                out = vault.retrieve_file(file_id, output_dir)
                print(f"  ✓ File saved to: {out}")
            except Exception as e:
                print(f"  ✗ Error: {e}")

        # ── Delete File ──
        elif choice == "5" and vault.is_unlocked:
            file_id = input("  File ID to delete: ").strip()
            confirm = input(f"  Permanently delete {file_id}? (yes/no): ").strip().lower()
            if confirm == "yes":
                try:
                    vault.delete_file(file_id)
                    print("  ✓ File deleted.")
                except Exception as e:
                    print(f"  ✗ Error: {e}")

        # ── Change Password ──
        elif choice == "6" and vault.is_unlocked:
            old_pw = getpass.getpass("  Current password: ")
            new_pw = getpass.getpass("  New password: ")
            if len(new_pw) < 8:
                print("  ✗ Password must be at least 8 characters.")
                continue
            new_pw2 = getpass.getpass("  Confirm new password: ")
            if new_pw != new_pw2:
                print("  ✗ Passwords do not match.")
                continue
            try:
                if vault.change_password(old_pw, new_pw):
                    print("  ✓ Password changed.")
                else:
                    print("  ✗ Current password is incorrect.")
            except Exception as e:
                print(f"  ✗ Error: {e}")

        # ── Lock ──
        elif choice == "7" and vault.is_unlocked:
            vault.lock()
            print("  ✓ Vault locked. Master key zeroed from memory.")

        else:
            print("  Invalid option.")


if __name__ == "__main__":
    main()
