#!/usr/bin/env python3
"""Non-destructive directory vault using AES-256-GCM and scrypt key wrapping."""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'CVLT1'

def b64(data):
    return base64.b64encode(data).decode('ascii')

def unb64(data):
    return base64.b64decode(data, validate=True)

def derive(passphrase, salt):
    return hashlib.scrypt(passphrase.encode('utf-8'), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)

def safe_rel(value):
    p = Path(value)
    if p.is_absolute() or '..' in p.parts or not p.parts or any(x in ('', '.') for x in p.parts):
        raise ValueError('Unsafe path in manifest')
    return p

def ensure_separate(source, target):
    s, t = source.resolve(), target.resolve()
    if s == t or s in t.parents or t in s.parents:
        raise ValueError('Input and output must be separate, non-nested directories')
    if target.exists():
        raise FileExistsError(f'Output already exists: {target}')

def files_in(root):
    for p in sorted(root.rglob('*')):
        if p.is_symlink():
            raise ValueError(f'Symlinks are not supported: {p}')
        if p.is_file():
            yield p

def encrypt(source, target, backup, password):
    if not source.is_dir() or source.is_symlink():
        raise ValueError('Source must be an existing real directory')
    ensure_separate(source, target)
    if backup.exists():
        raise FileExistsError('Backup path already exists')
    if source.resolve() == backup.resolve() or source.resolve() in backup.resolve().parents:
        raise ValueError('Backup cannot be inside source')
    if target.resolve() == backup.resolve() or target.resolve() in backup.resolve().parents:
        raise ValueError('Backup cannot be inside output')
    entries = list(files_in(source))
    target.mkdir(parents=True)
    try:
        key, salt, nonce = secrets.token_bytes(32), secrets.token_bytes(16), secrets.token_bytes(12)
        wrapped = AESGCM(derive(password, salt)).encrypt(nonce, key, b'CVLT-KEY-v1')
        key_record = {'format': 1, 'kdf': 'scrypt', 'salt': b64(salt), 'nonce': b64(nonce), 'wrapped_key': b64(wrapped)}
        manifest = {'format': 1, 'files': [], 'directories': []}
        for directory in sorted(p for p in source.rglob('*') if p.is_dir()):
            if directory.is_symlink():
                raise ValueError('Symlink directories are not supported')
            manifest['directories'].append(directory.relative_to(source).as_posix())
        for index, file in enumerate(entries):
            rel = file.relative_to(source).as_posix()
            data = file.read_bytes()
            file_nonce = secrets.token_bytes(12)
            cipher = AESGCM(key).encrypt(file_nonce, data, rel.encode('utf-8'))
            filename = f'{index:06d}.bin'
            (target / filename).write_bytes(MAGIC + file_nonce + cipher)
            manifest['files'].append({'path': rel, 'blob': filename, 'sha256': hashlib.sha256(data).hexdigest()})
            print(f'ENCRYPTED {rel} ({len(data)} bytes)')
        m_nonce = secrets.token_bytes(12)
        m_cipher = AESGCM(key).encrypt(m_nonce, json.dumps(manifest).encode('utf-8'), b'CVLT-MANIFEST-v1')
        (target / 'manifest.bin').write_bytes(MAGIC + m_nonce + m_cipher)
        (target / 'key.json').write_text(json.dumps(key_record, indent=2), encoding='utf-8')
        backup.parent.mkdir(parents=True, exist_ok=True)
        # Backup contains only the passphrase-wrapped key, never plaintext key material.
        with backup.open('x', encoding='utf-8') as f:
            json.dump(key_record, f, indent=2)
        print(f'SUCCESS: Encrypted {len(entries)} files into {target}')
        print(f'Key backup (passphrase required): {backup}')
        print('Original source files were NOT changed.')
    except Exception:
        shutil.rmtree(target)
        raise

def load_key(record_path, password):
    record = json.loads(record_path.read_text(encoding='utf-8'))
    if record.get('format') != 1 or record.get('kdf') != 'scrypt':
        raise ValueError('Unsupported key record')
    return AESGCM(derive(password, unb64(record['salt']))).decrypt(unb64(record['nonce']), unb64(record['wrapped_key']), b'CVLT-KEY-v1')

def decrypt(source, target, password, key_backup=None):
    if not source.is_dir() or source.is_symlink():
        raise ValueError('Vault directory does not exist')
    ensure_separate(source, target)
    key = load_key(key_backup or source / 'key.json', password)
    raw = (source / 'manifest.bin').read_bytes()
    if not raw.startswith(MAGIC) or len(raw) < len(MAGIC) + 12 + 16:
        raise ValueError('Invalid manifest')
    manifest = json.loads(AESGCM(key).decrypt(raw[5:17], raw[17:], b'CVLT-MANIFEST-v1'))
    if manifest.get('format') != 1:
        raise ValueError('Unsupported manifest format')
    target.mkdir(parents=True)
    try:
        for name in manifest['directories']:
            (target / safe_rel(name)).mkdir(parents=True, exist_ok=True)
        seen = set()
        for item in manifest['files']:
            rel = safe_rel(item['path'])
            blob = safe_rel(item['blob'])
            if len(blob.parts) != 1 or rel in seen:
                raise ValueError('Invalid or duplicate manifest entry')
            seen.add(rel)
            raw = (source / blob).read_bytes()
            if not raw.startswith(MAGIC) or len(raw) < 33:
                raise ValueError('Invalid encrypted file')
            data = AESGCM(key).decrypt(raw[5:17], raw[17:], rel.as_posix().encode('utf-8'))
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError(f'Integrity check failed for {rel}')
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            print(f'RESTORED {rel} (SHA-256 verified)')
        print(f'SUCCESS: Restored and verified {len(seen)} files into {target}')
        print('Encrypted vault files were NOT changed.')
    except Exception:
        shutil.rmtree(target)
        raise

def main():
    parser = argparse.ArgumentParser(description='Non-destructive AES-256-GCM directory vault')
    sub = parser.add_subparsers(dest='command', required=True)
    enc = sub.add_parser('encrypt')
    enc.add_argument('source', type=Path)
    enc.add_argument('output', type=Path)
    enc.add_argument('--backup', type=Path, required=True, help='Backup file outside the vault')
    dec = sub.add_parser('decrypt')
    dec.add_argument('vault', type=Path)
    dec.add_argument('output', type=Path)
    dec.add_argument('--key-backup', type=Path)
    args = parser.parse_args()
    password = getpass.getpass('Master passphrase: ')
    if not password:
        parser.error('Passphrase must not be empty')
    if args.command == 'encrypt':
        if len(password) < 12:
            parser.error('Use a passphrase of at least 12 characters')
        confirm = getpass.getpass('Confirm passphrase: ')
        if password != confirm:
            parser.error('Passphrases do not match')
    try:
        if args.command == 'encrypt':
            encrypt(args.source, args.output, args.backup, password)
        else:
            decrypt(args.vault, args.output, password, args.key_backup)
    except Exception as exc:
        print(f'ERROR: {exc.__class__.__name__}: {exc}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
