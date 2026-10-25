# Cryptographic Encryption Vault

Non-destructive Python command-line vault for directories using **AES-256-GCM** authenticated encryption, a random 256-bit data key, and **scrypt** passphrase-based key wrapping. Includes SHA-256 integrity checks and a passphrase-protected backup of the data key.

## Setup

```powershell
python -m pip install -r requirements.txt
```

## Windows PowerShell demonstration

```powershell
mkdir demo_input
Set-Content demo_input\hello.txt 'Hello, encrypted world!'
mkdir demo_input\notes
Set-Content demo_input\notes\sample.txt 'This is a test file.'
python vault.py encrypt demo_input encrypted_vault --backup vault_key_backup.json
python vault.py decrypt encrypted_vault restored_files
# Compare original and restored files:
Get-FileHash demo_input\hello.txt -Algorithm SHA256
Get-FileHash restored_files\hello.txt -Algorithm SHA256
Get-FileHash demo_input\notes\sample.txt -Algorithm SHA256
Get-FileHash restored_files\notes\sample.txt -Algorithm SHA256
```

Use a strong, unique passphrase (12+ characters); it is entered invisibly. Keep `vault_key_backup.json` safe and separate from the vault. **The backup is encrypted with the same passphrase; it cannot recover a forgotten passphrase.** Never commit personal vault data, backups, or plaintext to GitHub. The input is never deleted or modified; the output must not exist before each command. Keep backups of originals until verification succeeds.

## Limitations

For learning and moderate-sized files: this version loads each entire file into RAM. File contents and manifest paths are encrypted, but the number and approximate sizes of encrypted files are visible. Does not follow symlinks. File permissions, timestamps, and other metadata are not preserved. Avoid using it as your only backup or as an audited production vault.

## Submission screenshots

Capture your own terminal after encryption, after decryption, and after comparing SHA-256 hashes. The included sample log is a **demonstration**, not evidence of execution on your machine.
